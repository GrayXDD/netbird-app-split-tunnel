//go:build windows

package split

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/net"
	"github.com/shirou/gopsutil/v4/process"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
)

const (
	// connSnapshotTTL bounds how often the socket tables are re-read.
	connSnapshotTTL = 250 * time.Millisecond
	// procSnapshotTTL bounds how often PID-to-exe paths are re-resolved.
	procSnapshotTTL = 2 * time.Second
	// procSnapshotTimeout bounds a whole PID-to-exe refresh pass.
	procSnapshotTimeout = 2 * time.Second
)

// lazyRefresh serializes a lazily triggered snapshot refresh: the first
// caller after ttl runs refresh, concurrent callers block until it finishes.
// refresh must not hold the owner's locks, so the expensive work (OS table
// walks) runs unlocked and every caller that finds the snapshot stale
// observes a refresh completed within its own call.
type lazyRefresh struct {
	mu     sync.Mutex
	ttl    time.Duration
	lastAt time.Time
	done   chan struct{}
}

// ensure makes the snapshot fresh: it returns immediately when the last
// refresh is younger than ttl, runs refresh exactly once otherwise, and
// makes concurrent callers wait for that in-flight refresh.
func (r *lazyRefresh) ensure(refresh func()) {
	for {
		r.mu.Lock()
		if time.Since(r.lastAt) < r.ttl {
			r.mu.Unlock()
			return
		}
		if r.done == nil {
			done := make(chan struct{})
			r.done = done
			r.mu.Unlock()

			// Mark the cycle complete even if refresh panics, so waiters
			// can never block forever on a dead refresh.
			defer func() {
				r.mu.Lock()
				r.lastAt = time.Now()
				r.done = nil
				r.mu.Unlock()
				close(done)
			}()

			refresh()
			return
		}
		wait := r.done
		r.mu.Unlock()
		<-wait
	}
}

// tcpFlowKey matches a TCP socket by its full 4-tuple.
type tcpFlowKey struct {
	localIP    netip.Addr
	remoteIP   netip.Addr
	localPort  uint16
	remotePort uint16
}

// udpLocalKey matches a UDP socket by its local endpoint only; UDP has no
// reliable remote endpoint in the socket tables.
type udpLocalKey struct {
	ip   netip.Addr
	port uint16
}

// processClassifier attributes connections to owning executables using
// periodic gopsutil snapshots of the socket tables (keyed by endpoint) and of
// process executable paths (keyed by PID). Snapshots are refreshed lazily
// under a TTL; the refresh walks run without the lookup lock, so concurrent
// lookups only ever queue on the short map accesses.
type processClassifier struct {
	mu sync.Mutex

	conns      lazyRefresh
	tcpByFlow  map[tcpFlowKey]int32
	udpByLocal map[udpLocalKey]int32

	exe      lazyRefresh
	exeByPid map[int32]string
}

// NewProcessClassifier returns a Classifier that resolves the owning
// executable of a connection on Windows.
func NewProcessClassifier() Classifier {
	return &processClassifier{
		conns:      lazyRefresh{ttl: connSnapshotTTL},
		tcpByFlow:  make(map[tcpFlowKey]int32),
		udpByLocal: make(map[udpLocalKey]int32),
		exe:        lazyRefresh{ttl: procSnapshotTTL},
		exeByPid:   make(map[int32]string),
	}
}

// Owner implements Classifier. Any snapshot or lookup failure yields
// ok=false so the engine fails closed to VerdictTunnel.
func (c *processClassifier) Owner(key conntrack.ConnKey, proto Protocol) (string, bool) {
	c.conns.ensure(c.loadConns)

	localIP := key.SrcIP.Unmap()
	remoteIP := key.DstIP.Unmap()

	var pid int32
	var found bool
	c.mu.Lock()
	switch proto {
	case ProtoTCP:
		pid, found = c.tcpByFlow[tcpFlowKey{
			localIP:    localIP,
			remoteIP:   remoteIP,
			localPort:  key.SrcPort,
			remotePort: key.DstPort,
		}]
	case ProtoUDP:
		pid, found = c.udpByLocal[udpLocalKey{ip: localIP, port: key.SrcPort}]
	default:
		c.mu.Unlock()
		return "", false
	}
	c.mu.Unlock()
	if !found {
		return "", false
	}

	c.exe.ensure(c.loadExePaths)
	c.mu.Lock()
	exe, ok := c.exeByPid[pid]
	c.mu.Unlock()
	return exe, ok
}

// loadConns re-reads the TCP and UDP socket tables and publishes the new
// indexes. On error the indexes are emptied, which makes lookups miss until
// the next refresh.
func (c *processClassifier) loadConns() {
	tcpConns, tcpErr := net.Connections("tcp")
	udpConns, udpErr := net.Connections("udp")
	if tcpErr != nil || udpErr != nil {
		c.mu.Lock()
		c.tcpByFlow = make(map[tcpFlowKey]int32)
		c.udpByLocal = make(map[udpLocalKey]int32)
		c.mu.Unlock()
		return
	}

	tcpByFlow := make(map[tcpFlowKey]int32, len(tcpConns))
	for _, conn := range tcpConns {
		localIP, err := netip.ParseAddr(conn.Laddr.IP)
		if err != nil {
			continue
		}
		remoteIP, err := netip.ParseAddr(conn.Raddr.IP)
		if err != nil {
			continue
		}
		tcpByFlow[tcpFlowKey{
			localIP:    localIP.Unmap(),
			remoteIP:   remoteIP.Unmap(),
			localPort:  uint16(conn.Laddr.Port),
			remotePort: uint16(conn.Raddr.Port),
		}] = conn.Pid
	}

	udpByLocal := make(map[udpLocalKey]int32, len(udpConns))
	for _, conn := range udpConns {
		localIP, err := netip.ParseAddr(conn.Laddr.IP)
		if err != nil {
			continue
		}
		udpByLocal[udpLocalKey{ip: localIP.Unmap(), port: uint16(conn.Laddr.Port)}] = conn.Pid
	}

	c.mu.Lock()
	c.tcpByFlow = tcpByFlow
	c.udpByLocal = udpByLocal
	c.mu.Unlock()
}

// loadExePaths re-resolves PID-to-executable basenames. The whole pass is
// bounded by procSnapshotTimeout; on error the map is emptied, which makes
// lookups miss until the next refresh.
func (c *processClassifier) loadExePaths() {
	exeByPid := make(map[int32]string)
	ctx, cancel := context.WithTimeout(context.Background(), procSnapshotTimeout)
	defer cancel()

	pids, err := process.PidsWithContext(ctx)
	if err == nil {
		for _, pid := range pids {
			if ctx.Err() != nil {
				break
			}
			p := &process.Process{Pid: pid}
			path, err := p.ExeWithContext(ctx)
			if err != nil || path == "" {
				continue
			}
			exeByPid[pid] = strings.ToLower(filepath.Base(path))
		}
	}

	c.mu.Lock()
	c.exeByPid = exeByPid
	c.mu.Unlock()
}
