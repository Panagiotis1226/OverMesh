package daemon

import (
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panagiotis1226/overmesh/internal/overdrop"
)

// Transfer is one outbound OverDrop send, tracked so GUIs can start a
// drop without blocking and poll its progress.
type Transfer struct {
	ID        int64  `json:"id"`
	File      string `json:"file"`
	Peer      string `json:"peer"`
	Sent      int64  `json:"sent"`
	Total     int64  `json:"total"`
	State     string `json:"state"` // sending | done | error
	Error     string `json:"error,omitempty"`
	StartedAt int64  `json:"started_at"` // unix seconds
}

type transferEntry struct {
	mu sync.Mutex
	t  Transfer
}

type transfers struct {
	mu     sync.Mutex
	nextID atomic.Int64
	byID   map[int64]*transferEntry
}

// StartDrop begins sending file to the named peer and returns a
// transfer ID immediately; progress is visible via Transfers().
func (d *Daemon) StartDrop(file, peer string, port uint16) (int64, error) {
	if port == 0 {
		port = overdrop.DefaultPort
	}
	if _, err := os.Stat(file); err != nil {
		return 0, err
	}

	st := d.Status()
	if !st.Running {
		return 0, fmt.Errorf("not connected")
	}
	var dstIP string
	for _, p := range st.Peers {
		if strings.EqualFold(p.Hostname, peer) {
			if !p.Online {
				return 0, fmt.Errorf("%s is offline", p.Hostname)
			}
			dstIP = p.IPv4
			break
		}
	}
	if dstIP == "" {
		return 0, fmt.Errorf("no peer named %q", peer)
	}
	dst, err := netip.ParseAddr(dstIP)
	if err != nil {
		return 0, err
	}

	d.xfers.mu.Lock()
	if d.xfers.byID == nil {
		d.xfers.byID = make(map[int64]*transferEntry)
	}
	id := d.xfers.nextID.Add(1)
	entry := &transferEntry{t: Transfer{
		ID: id, File: file, Peer: peer,
		State: "sending", StartedAt: time.Now().Unix(),
	}}
	d.xfers.byID[id] = entry
	d.xfers.mu.Unlock()

	go func() {
		err := overdrop.Send(dst, port, file, func(sent, total int64) {
			entry.mu.Lock()
			entry.t.Sent, entry.t.Total = sent, total
			entry.mu.Unlock()
		})
		entry.mu.Lock()
		if err != nil {
			entry.t.State, entry.t.Error = "error", err.Error()
		} else {
			entry.t.State = "done"
			entry.t.Sent = entry.t.Total
		}
		entry.mu.Unlock()
	}()
	return id, nil
}

// Transfers lists outbound drops, newest first.
func (d *Daemon) Transfers() []Transfer {
	d.xfers.mu.Lock()
	entries := make([]*transferEntry, 0, len(d.xfers.byID))
	for _, e := range d.xfers.byID {
		entries = append(entries, e)
	}
	d.xfers.mu.Unlock()

	out := make([]Transfer, 0, len(entries))
	for _, e := range entries {
		e.mu.Lock()
		out = append(out, e.t)
		e.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out
}
