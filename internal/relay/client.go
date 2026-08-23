package relay

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// Client maintains a connection to one relay and exchanges WireGuard
// payloads addressed by node public key. It reconnects with backoff until
// closed; Send during an outage returns an error the caller may ignore
// (WireGuard retransmits).
type Client struct {
	url      string // e.g. "http://host:8080/relay" or "https://host/relay"
	priv     [32]byte
	pub      [32]byte
	onPacket func(src [32]byte, payload []byte)
	logf     func(string, ...any)
	// dialControl, when set, is applied to the TCP dial (the daemon
	// stamps SO_MARK so relay traffic bypasses exit-node routing).
	dialControl func(network, address string, c syscall.RawConn) error

	mu     sync.Mutex
	conn   net.Conn
	up     bool
	closed bool
	cancel context.CancelFunc
}

// NewClient starts a client for relayURL, authenticating with the node
// private key. onPacket runs on the read goroutine for every relayed
// payload. dialControl (optional) is applied to the underlying TCP
// socket before connecting.
func NewClient(relayURL string, nodePriv, nodePub [32]byte, onPacket func(src [32]byte, payload []byte), logf func(string, ...any), dialControl func(network, address string, c syscall.RawConn) error) *Client {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{url: relayURL, priv: nodePriv, pub: nodePub, onPacket: onPacket, logf: logf, cancel: cancel, dialControl: dialControl}
	go c.run(ctx)
	return c
}

// Connected reports whether the relay link is currently up.
func (c *Client) Connected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.up
}

// URL returns the relay URL this client targets.
func (c *Client) URL() string { return c.url }

// Send relays payload to the node with public key dst.
func (c *Client) Send(dst [32]byte, payload []byte) error {
	c.mu.Lock()
	conn, up := c.conn, c.up
	c.mu.Unlock()
	if !up || conn == nil {
		return fmt.Errorf("relay: not connected")
	}
	body := make([]byte, 32+len(payload))
	copy(body[:32], dst[:])
	copy(body[32:], payload)
	c.mu.Lock() // serialize frame writes
	defer c.mu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("relay: not connected")
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return writeFrame(c.conn, frameSend, body)
}

// Close stops the client permanently.
func (c *Client) Close() {
	c.mu.Lock()
	c.closed = true
	if c.conn != nil {
		c.conn.Close()
	}
	c.mu.Unlock()
	c.cancel()
}

func (c *Client) run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		err := c.session(ctx)
		c.mu.Lock()
		c.up, c.conn = false, nil
		closed := c.closed
		c.mu.Unlock()
		if closed || ctx.Err() != nil {
			return
		}
		c.logf("relay: connection to %s lost (%v), retrying in %v", c.url, err, backoff)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

// session dials, upgrades, authenticates, then reads frames until error.
func (c *Client) session(ctx context.Context) error {
	conn, br, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := c.authenticate(conn, br); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return fmt.Errorf("closed")
	}
	c.conn = conn
	c.up = true
	c.mu.Unlock()
	c.logf("relay: connected to %s", c.url)

	// Keepalive pinger.
	pingCtx, stopPing := context.WithCancel(ctx)
	defer stopPing()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-pingCtx.Done():
				return
			case <-t.C:
				c.mu.Lock()
				if c.conn != nil {
					_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := writeFrame(c.conn, framePing, nil); err != nil {
						c.conn.Close()
					}
				}
				c.mu.Unlock()
			}
		}
	}()

	buf := make([]byte, maxFrameLen)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		typ, body, err := readFrame(br, buf)
		if err != nil {
			return err
		}
		switch typ {
		case frameRecv:
			if len(body) < 32 {
				continue
			}
			var src [32]byte
			copy(src[:], body[:32])
			// Copy: body aliases the shared read buffer.
			payload := append([]byte(nil), body[32:]...)
			c.onPacket(src, payload)
		case framePong: // keepalive satisfied by resetting the deadline
		}
	}
}

// dial opens the TCP/TLS connection and performs the HTTP upgrade.
func (c *Client) dial(ctx context.Context) (net.Conn, *bufio.Reader, error) {
	u, err := url.Parse(c.url)
	if err != nil {
		return nil, nil, fmt.Errorf("relay url %q: %w", c.url, err)
	}
	host := u.Host
	if u.Port() == "" {
		if u.Scheme == "https" {
			host = net.JoinHostPort(u.Hostname(), "443")
		} else {
			host = net.JoinHostPort(u.Hostname(), "80")
		}
	}

	d := &net.Dialer{Timeout: 15 * time.Second, Control: c.dialControl}
	var conn net.Conn
	if u.Scheme == "https" {
		conn, err = tls.DialWithDialer(d, "tcp", host, &tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		conn, err = d.DialContext(ctx, "tcp", host)
	}
	if err != nil {
		return nil, nil, err
	}

	path := u.Path
	if path == "" {
		path = UpgradePath
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: %s\r\nConnection: Upgrade\r\n\r\n",
		path, u.Hostname(), ProtocolName)
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, nil, err
	}
	br := bufio.NewReader(conn)
	// Read the 101 response headers (terminated by a blank line).
	status, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	if len(status) < 12 || status[9:12] != "101" {
		conn.Close()
		return nil, nil, fmt.Errorf("relay: unexpected response %q", status)
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return conn, br, nil
}

// authenticate answers the server's challenge.
func (c *Client) authenticate(conn net.Conn, br *bufio.Reader) error {
	buf := make([]byte, maxFrameLen)
	typ, body, err := readFrame(br, buf)
	if err != nil {
		return err
	}
	if typ != frameChallenge || len(body) != 32+24 {
		return fmt.Errorf("relay: bad challenge")
	}
	var serverEph [32]byte
	var nonce [24]byte
	copy(serverEph[:], body[:32])
	copy(nonce[:], body[32:])

	sealed := box.Seal(nil, nonce[:], &nonce, &serverEph, &c.priv)
	auth := make([]byte, 32+len(sealed))
	copy(auth[:32], c.pub[:])
	copy(auth[32:], sealed)
	if err := writeFrame(conn, frameAuth, auth); err != nil {
		return err
	}
	typ, _, err = readFrame(br, buf)
	if err != nil {
		return err
	}
	if typ != frameOK {
		return fmt.Errorf("relay: auth rejected")
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}
