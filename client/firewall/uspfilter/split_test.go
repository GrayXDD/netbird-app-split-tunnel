package uspfilter

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/bypass"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	nbiface "github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/split"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// fixedClassifier returns a canned attribution and counts lookups; it backs
// the engine white-box in tests instead of the real process classifier.
type fixedClassifier struct {
	exe   string
	ok    bool
	calls atomic.Int64
}

func (c *fixedClassifier) Owner(conntrack.ConnKey, split.Protocol) (string, bool) {
	c.calls.Add(1)
	return c.exe, c.ok
}

// fakeTUNWriter records the answer packets the bypass stack hands back to the
// host.
type fakeTUNWriter struct {
	mu     sync.Mutex
	writes [][]byte
}

func (f *fakeTUNWriter) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bufs {
		f.writes = append(f.writes, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}

// newSplitTestManager returns a manager whose interface has a valid overlay
// address and a fake TUN writer, and whose bypass dialer never dials the
// network.
func newSplitTestManager(tb testing.TB) *Manager {
	tb.Helper()

	// SetSplitTunnel requires advanced routing; recompute the flag from the
	// (test-controlled) environment like the daemon does at startup.
	nbnet.Init()

	tun := &fakeTUNWriter{}
	wgIP := netip.MustParseAddr("100.10.0.1")
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{IP: wgIP, Network: netip.PrefixFrom(wgIP, 24)}
		},
		TunFunc: func() bypass.TUNWriter { return tun },
	}

	m, err := Create(Config{IFace: ifaceMock, FlowLogger: flowLogger, MTU: nbiface.DefaultMTU})
	require.NoError(tb, err)

	m.newBypassDialerFn = func() bypass.DialContextFunc {
		return func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("dialing is disabled in tests")
		}
	}
	return m
}

func closeSplitManager(tb testing.TB, m *Manager) {
	tb.Helper()
	require.NoError(tb, m.Close(nil))
}

func generateUDPPacket(tb testing.TB, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	tb.Helper()

	ipLayer := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	require.NoError(tb, udpLayer.SetNetworkLayerForChecksum(ipLayer))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(tb, gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, gopacket.Payload([]byte{})))
	return buf.Bytes()
}

func TestSetSplitTunnel(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	require.Nil(t, m.splitEngine.Load(), "no engine by default")

	require.NoError(t, m.SetSplitTunnel(split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}}))
	require.NotNil(t, m.splitEngine.Load())

	require.NoError(t, m.SetSplitTunnel(split.Settings{Mode: split.ModeOff, Apps: []string{"opera.exe"}}))
	require.Nil(t, m.splitEngine.Load(), "mode off must clear the engine")
	require.Nil(t, m.bypassStack.Load(), "mode off must clear the bypass stack")
}

func TestFilterOutboundWithoutSplitEngine(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	tcpPacket := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53211, 443, uint16(conntrack.TCPSyn))
	require.False(t, m.filterOutbound(tcpPacket, len(tcpPacket)))

	udpPacket := generateUDPPacket(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53212, 53)
	require.False(t, m.filterOutbound(udpPacket, len(udpPacket)))
}

func TestFilterOutboundModeOffIsTunnel(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	c := &fixedClassifier{exe: "opera.exe", ok: true}
	m.splitEngine.Store(split.NewEngine(split.Settings{Mode: split.ModeOff, Apps: []string{"opera.exe"}}, c))

	packet := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53213, 443, uint16(conntrack.TCPSyn))
	require.False(t, m.filterOutbound(packet, len(packet)))
	require.Zero(t, c.calls.Load(), "mode off must not consult the classifier")
}

func TestFilterOutboundTunnelVerdict(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	// Include mode with opera.exe listed: the flow's owner is listed, so the
	// packet stays on the tunnel path.
	m.splitEngine.Store(split.NewEngine(split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}}, &fixedClassifier{exe: "opera.exe", ok: true}))

	tcpPacket := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53214, 443, uint16(conntrack.TCPSyn))
	require.False(t, m.filterOutbound(tcpPacket, len(tcpPacket)))

	udpPacket := generateUDPPacket(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53215, 53)
	require.False(t, m.filterOutbound(udpPacket, len(udpPacket)))
}

func TestFilterOutboundOverlayDestinationIsTunnel(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	c := &fixedClassifier{exe: "chrome.exe", ok: true}
	m.splitEngine.Store(split.NewEngine(split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}}, c))

	// Destination inside the overlay network must tunnel without a decision.
	packet := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("100.10.0.55"), 53216, 22, uint16(conntrack.TCPSyn))
	require.False(t, m.filterOutbound(packet, len(packet)))
	require.Zero(t, c.calls.Load(), "overlay destinations must not consult the classifier")
}

func TestFilterOutboundBypassVerdictDropsFromTunnel(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	// Include mode with only opera.exe listed: the flow's owner chrome.exe
	// bypasses. The dialer never dials and the TUN is a fake writer, so the
	// verdict only decides the drop from the tunnel path.
	m.splitEngine.Store(split.NewEngine(split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}}, &fixedClassifier{exe: "chrome.exe", ok: true}))

	tcpPacket := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53217, 443, uint16(conntrack.TCPSyn))
	require.True(t, m.filterOutbound(tcpPacket, len(tcpPacket)), "bypass verdict must drop the packet from the tunnel path")

	udpPacket := generateUDPPacket(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53218, 53)
	require.True(t, m.filterOutbound(udpPacket, len(udpPacket)), "bypass verdict must drop the packet from the tunnel path")

	require.NotNil(t, m.bypassStack.Load(), "the bypass stack must be created lazily on the first bypass verdict")
}

func TestFilterOutboundBypassStackErrorTunnels(t *testing.T) {
	wgIP := netip.MustParseAddr("100.10.0.1")
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{IP: wgIP, Network: netip.PrefixFrom(wgIP, 24)}
		},
		// No TUN device: bypass stack creation fails, traffic tunnels.
		TunFunc: func() bypass.TUNWriter { return nil },
	}

	m, err := Create(Config{IFace: ifaceMock, FlowLogger: flowLogger, MTU: nbiface.DefaultMTU})
	require.NoError(t, err)
	defer closeSplitManager(t, m)

	m.splitEngine.Store(split.NewEngine(split.Settings{Mode: split.ModeExclude, Apps: []string{"opera.exe"}}, &fixedClassifier{exe: "opera.exe", ok: true}))

	packet := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("8.8.8.8"), 53219, 443, uint16(conntrack.TCPSyn))
	require.False(t, m.filterOutbound(packet, len(packet)), "bypass stack init failure must tunnel (fail-closed)")
	require.Nil(t, m.bypassStack.Load(), "a failed init must not cache a stack")
}

// TestSetSplitTunnelRequiresAdvancedRouting verifies the fail-closed gate:
// without advanced routing the bypass dialer does not bind sockets to the
// physical interface, so bypassed traffic would loop back into the tunnel.
// Splitting must then be refused instead of half-installed.
func TestSetSplitTunnelRequiresAdvancedRouting(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	t.Setenv("NB_USE_LEGACY_ROUTING", "true")
	nbnet.Init()
	require.False(t, nbnet.AdvancedRouting())

	err := m.SetSplitTunnel(split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}})
	require.Error(t, err, "split tunnel must be refused without advanced routing")
	require.Nil(t, m.splitEngine.Load(), "a refused split must not install an engine")

	// Mode off stays a no-op that always succeeds.
	require.NoError(t, m.SetSplitTunnel(split.Settings{Mode: split.ModeOff}))
}

// TestFilterOutboundRoutedNetworkIsTunnel verifies that destinations covered
// by NetBird-managed network routes stay on the tunnel: the split bypass
// dials outside the tunnel and must never capture corporate routed traffic.
func TestFilterOutboundRoutedNetworkIsTunnel(t *testing.T) {
	m := newSplitTestManager(t)
	defer closeSplitManager(t, m)

	require.NoError(t, m.SetSplitTunnelRoutes([]netip.Prefix{netip.MustParsePrefix("10.10.0.0/24")}))

	c := &fixedClassifier{exe: "chrome.exe", ok: true}
	m.splitEngine.Store(split.NewEngine(split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}}, c))

	packet := generateTCPPacketWithFlags(t, net.ParseIP("100.10.0.1"), net.ParseIP("10.10.0.5"), 53220, 22, uint16(conntrack.TCPSyn))
	require.False(t, m.filterOutbound(packet, len(packet)), "routed networks must stay on the tunnel")
	require.Zero(t, c.calls.Load(), "routed networks must not consult the classifier")
}
