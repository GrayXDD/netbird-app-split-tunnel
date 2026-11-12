package iface

import (
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgbackend"
)

// recordingTUN is a raw TUN device that records written packets.
type recordingTUN struct {
	mu     sync.Mutex
	writes [][]byte
}

func (t *recordingTUN) File() *os.File { return nil }

func (t *recordingTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, nil
}

func (t *recordingTUN) Write(bufs [][]byte, offset int) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, b := range bufs {
		t.writes = append(t.writes, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

func (t *recordingTUN) MTU() (int, error)                 { return 1280, nil }
func (t *recordingTUN) Name() (string, error)             { return "wt0", nil }
func (t *recordingTUN) Events() <-chan wgbackend.TUNEvent { return nil }
func (t *recordingTUN) Close() error                      { return nil }
func (t *recordingTUN) BatchSize() int                    { return 1 }

func (t *recordingTUN) written() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([][]byte(nil), t.writes...)
}

// stubTunDevice implements WGTunDevice for tests that only need the filtered
// device; every other method panics via the nil embedded interface.
type stubTunDevice struct {
	WGTunDevice
	filtered *device.FilteredDevice
}

func (d *stubTunDevice) FilteredDevice() *device.FilteredDevice { return d.filtered }

// dropAllFilter drops every packet in both directions.
type dropAllFilter struct{}

func (dropAllFilter) FilterOutbound([]byte, int) bool { return true }
func (dropAllFilter) FilterInbound([]byte, int) bool  { return true }

func (dropAllFilter) SetUDPPacketHook(netip.Addr, uint16, func([]byte) bool) {}
func (dropAllFilter) SetTCPPacketHook(netip.Addr, uint16, func([]byte) bool) {}

// TestTunSkipsInboundFilter verifies that Tun returns a writer to the raw TUN
// device, not the FilteredDevice: packets handed back to the host (e.g. split
// tunnel bypass answers) carry no inbound conntrack or ACL state and must not
// run through FilterInbound, which would drop them.
func TestTunSkipsInboundFilter(t *testing.T) {
	raw := &recordingTUN{}
	filtered := &device.FilteredDevice{TUN: raw}
	w := &WGIface{tun: &stubTunDevice{filtered: filtered}}
	require.NoError(t, w.SetFilter(dropAllFilter{}))

	sink := w.Tun()
	require.NotNil(t, sink)

	packet := []byte{0x45, 0, 0, 20}
	n, err := sink.Write([][]byte{packet}, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n)

	written := raw.written()
	require.Len(t, written, 1, "write must reach the raw device even with a drop-all inbound filter")
	require.Equal(t, packet, written[0])
}

func TestTunNilWithoutFilteredDevice(t *testing.T) {
	w := &WGIface{tun: &stubTunDevice{}}
	require.Nil(t, w.Tun())
}
