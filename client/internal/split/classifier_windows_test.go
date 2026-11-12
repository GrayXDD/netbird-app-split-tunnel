//go:build windows

package split

import (
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
)

// TestProcessClassifierAttributesLocalConnection drives the classifier over a
// real loopback TCP connection: the owning executable must resolve to this
// test binary through the socket table and the PID snapshot.
func TestProcessClassifierAttributesLocalConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	local, ok := conn.LocalAddr().(*net.TCPAddr)
	require.True(t, ok)
	remote, ok := ln.Addr().(*net.TCPAddr)
	require.True(t, ok)

	c := NewProcessClassifier()
	key := conntrack.ConnKey{
		SrcIP:   netip.MustParseAddr(local.IP.String()),
		DstIP:   netip.MustParseAddr(remote.IP.String()),
		SrcPort: uint16(local.Port),
		DstPort: uint16(remote.Port),
	}

	exe, ok := c.Owner(key, ProtoTCP)
	require.True(t, ok, "attribution of a live loopback connection must succeed")

	self, err := os.Executable()
	require.NoError(t, err)
	require.Equal(t, strings.ToLower(filepath.Base(self)), exe)
}

// TestProcessClassifierConcurrentOwner verifies that concurrent lookups
// serialize their snapshot refreshes without deadlocking: one goroutine may
// walk the socket and process tables while the others wait for the fresh
// snapshot.
func TestProcessClassifierConcurrentOwner(t *testing.T) {
	c := NewProcessClassifier()
	key := conntrack.ConnKey{
		SrcIP:   netip.MustParseAddr("127.0.0.1"),
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		SrcPort: 1234,
		DstPort: 80,
	}

	var wg sync.WaitGroup
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.Owner(key, ProtoTCP)
		}()
	}
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("concurrent Owner calls deadlocked")
	}
}
