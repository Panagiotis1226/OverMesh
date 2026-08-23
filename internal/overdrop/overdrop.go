// Package overdrop is OverMesh's Taildrop-style file transfer.
//
// Every daemon runs a small HTTP receiver bound ONLY to its overlay
// IPv4, so it is reachable exclusively over WireGuard. The sender's
// identity is its overlay source address — WireGuard's cryptokey
// routing binds that address to exactly one peer key, so no extra
// authentication is needed. Access rules apply like to any other
// overlay traffic: deny tcp/41645 and drops are blocked.
//
// Protocol (plain HTTP over the tunnel; payloads are already encrypted
// by WireGuard):
//
//	GET  /offset?name=F&size=N   -> {"offset": M}   resume point
//	PUT  /put?name=F&size=N&offset=M                body = bytes M..N
//
// The receiver stages partial files as "<name>.<size>.part" in the
// inbox and renames them into place atomically when complete, so a
// finished file never appears half-written. Each sender gets its own
// subdirectory (inbox/<sender-hostname>/) — names can't collide across
// peers and the origin is self-evident.
package overdrop

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultPort is OverDrop's well-known TCP port on the overlay.
const DefaultPort = 41645

// PeerNamer resolves an overlay address to a peer hostname ("" =
// unknown peer, the request is rejected).
type PeerNamer func(addr netip.Addr) string

// Server is the receiving side.
type Server struct {
	dir      string // inbox root
	peerName PeerNamer
	logf     func(string, ...any)

	mu  sync.Mutex
	lis net.Listener
	// perFile serializes writes to one staged file; concurrent sends of
	// the same file would corrupt the .part.
	busy map[string]bool
}

// NewServer returns an unstarted receiver that stores files under dir.
func NewServer(dir string, peerName PeerNamer, logf func(string, ...any)) *Server {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Server{dir: dir, peerName: peerName, logf: logf, busy: make(map[string]bool)}
}

// Start listens on ip:port (the node's overlay IPv4).
func (s *Server) Start(ip netip.Addr, port uint16) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	lis, err := net.Listen("tcp", netip.AddrPortFrom(ip, port).String())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.lis = lis
	s.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /offset", s.handleOffset)
	mux.HandleFunc("PUT /put", s.handlePut)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(lis) }()
	s.logf("overdrop: receiving on %s, inbox %s", lis.Addr(), s.dir)
	return nil
}

// Close stops the listener.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lis != nil {
		s.lis.Close()
		s.lis = nil
	}
}

// sender authenticates the request by overlay source address.
func (s *Server) sender(r *http.Request) (string, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return "", err
	}
	name := s.peerName(addr.Unmap())
	if name == "" {
		return "", errors.New("unknown peer")
	}
	return name, nil
}

// params validates the transfer parameters shared by both endpoints.
func params(r *http.Request) (name string, size int64, err error) {
	name = filepath.Base(strings.TrimSpace(r.URL.Query().Get("name")))
	if name == "" || name == "." || name == ".." || name == "/" ||
		strings.ContainsAny(name, "/\\\x00") {
		return "", 0, errors.New("bad name")
	}
	size, err = strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
	if err != nil || size < 0 {
		return "", 0, errors.New("bad size")
	}
	return name, size, nil
}

func (s *Server) paths(sender, name string, size int64) (dir, part, final string) {
	dir = filepath.Join(s.dir, sender)
	part = filepath.Join(dir, fmt.Sprintf("%s.%d.part", name, size))
	final = filepath.Join(dir, name)
	return
}

func (s *Server) handleOffset(w http.ResponseWriter, r *http.Request) {
	from, err := s.sender(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	name, size, err := params(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, part, _ := s.paths(from, name, size)
	var offset int64
	if fi, err := os.Stat(part); err == nil {
		offset = fi.Size()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int64{"offset": offset})
}

func (s *Server) handlePut(w http.ResponseWriter, r *http.Request) {
	from, err := s.sender(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	name, size, err := params(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 || offset > size {
		http.Error(w, "bad offset", http.StatusBadRequest)
		return
	}
	dir, part, final := s.paths(from, name, size)

	key := part
	s.mu.Lock()
	if s.busy[key] {
		s.mu.Unlock()
		http.Error(w, "transfer already in progress", http.StatusConflict)
		return
	}
	s.busy[key] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.busy, key)
		s.mu.Unlock()
	}()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f, err := os.OpenFile(part, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// The client must resume exactly where the staged file ends.
	if fi, err := f.Stat(); err != nil || fi.Size() != offset {
		http.Error(w, fmt.Sprintf("offset mismatch: have %d", fileSize(f)), http.StatusConflict)
		return
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	n, err := io.Copy(f, r.Body)
	got := offset + n
	if err != nil || got > size {
		// Partial write is fine — the .part keeps what arrived and the
		// next attempt resumes from there. Oversized means a bad sender.
		if got > size {
			os.Remove(part)
			http.Error(w, "more bytes than announced", http.StatusBadRequest)
			return
		}
		http.Error(w, fmt.Sprintf("short transfer at %d/%d", got, size), http.StatusInternalServerError)
		return
	}
	if got < size {
		http.Error(w, fmt.Sprintf("short transfer at %d/%d", got, size), http.StatusBadRequest)
		return
	}

	if err := f.Sync(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f.Close()
	// Never overwrite an existing file: dedupe like browsers do.
	dst := dedupePath(final)
	if err := os.Rename(part, dst); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.logf("overdrop: received %q (%d bytes) from %s -> %s", name, size, from, dst)
	w.WriteHeader(http.StatusNoContent)
}

func fileSize(f *os.File) int64 {
	fi, err := f.Stat()
	if err != nil {
		return -1
	}
	return fi.Size()
}

// dedupePath returns path, or "name (2).ext" style variants until free.
func dedupePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}
	dir, base := filepath.Dir(path), filepath.Base(path)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for i := 2; ; i++ {
		p := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return p
		}
	}
}

// --- inbox listing (for the CLI / UI) ---

// InboxFile is one received (or in-flight) file.
type InboxFile struct {
	From    string `json:"from"`
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Partial bool   `json:"partial"`
	ModTime int64  `json:"mod_time"`
	Path    string `json:"path"`
}

// ListInbox walks the inbox directory.
func ListInbox(dir string) ([]InboxFile, error) {
	var out []InboxFile
	senders, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, sd := range senders {
		if !sd.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(dir, sd.Name()))
		if err != nil {
			continue
		}
		for _, fe := range files {
			fi, err := fe.Info()
			if err != nil || fe.IsDir() {
				continue
			}
			out = append(out, InboxFile{
				From:    sd.Name(),
				Name:    fe.Name(),
				Size:    fi.Size(),
				Partial: strings.HasSuffix(fe.Name(), ".part"),
				ModTime: fi.ModTime().Unix(),
				Path:    filepath.Join(dir, sd.Name(), fe.Name()),
			})
		}
	}
	return out, nil
}

// --- sending (used by the CLI via the overlay) ---

// Send streams path to the receiver at dst (overlay IPv4), resuming
// from whatever the receiver already holds. progress (optional) is
// called with (sentBytes, totalBytes).
func Send(dst netip.Addr, port uint16, path string, progress func(int64, int64)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return errors.New("cannot send a directory (zip it first)")
	}
	size := fi.Size()
	name := filepath.Base(path)
	base := fmt.Sprintf("http://%s", netip.AddrPortFrom(dst, port))
	q := fmt.Sprintf("name=%s&size=%d", urlEscape(name), size)

	cli := &http.Client{Timeout: 0} // large files: no overall timeout

	// Where should we resume from?
	resp, err := cli.Get(base + "/offset?" + q)
	if err != nil {
		return fmt.Errorf("receiver unreachable (is the peer online and overdrop enabled?): %w", err)
	}
	var off struct {
		Offset int64 `json:"offset"`
	}
	err = json.NewDecoder(resp.Body).Decode(&off)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		return fmt.Errorf("offset query failed: %s", resp.Status)
	}
	if off.Offset > size {
		off.Offset = 0
	}
	if _, err := f.Seek(off.Offset, io.SeekStart); err != nil {
		return err
	}

	body := io.Reader(f)
	if progress != nil {
		body = &progressReader{r: f, base: off.Offset, total: size, cb: progress}
	}
	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("%s/put?%s&offset=%d", base, q, off.Offset), body)
	if err != nil {
		return err
	}
	req.ContentLength = size - off.Offset
	resp2, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("transfer interrupted (rerun to resume): %w", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp2.Body, 512))
		return fmt.Errorf("receiver rejected the file: %s: %s", resp2.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

type progressReader struct {
	r     io.Reader
	base  int64
	sent  int64
	total int64
	cb    func(int64, int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.sent += int64(n)
	p.cb(p.base+p.sent, p.total)
	return n, err
}

func urlEscape(s string) string {
	// Minimal: names already exclude / and \; escape the URL specials.
	r := strings.NewReplacer("%", "%25", "&", "%26", "+", "%2B", "#", "%23", "?", "%3F", " ", "%20")
	return r.Replace(s)
}
