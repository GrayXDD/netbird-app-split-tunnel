package bypass

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

var (
	clientAddr = netip.MustParseAddr("100.64.0.2") // host application
	tunAddr    = netip.MustParseAddr("100.64.0.1") // wt0 address
	remoteAddr = netip.MustParseAddr("1.2.3.4")
	dnsAddr    = netip.MustParseAddr("8.8.8.8")
)

// fakeTUN records the packets the stack hands back to the host.
type fakeTUN struct {
	mu      sync.Mutex
	packets [][]byte
	signal  chan struct{}
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{signal: make(chan struct{}, 256)}
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		f.packets = append(f.packets, pkt)
		f.signal <- struct{}{}
	}
	return len(bufs), nil
}

func (f *fakeTUN) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.packets)
}

func (f *fakeTUN) next() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	pkt := f.packets[len(f.packets)-1]
	return pkt
}

// waitPacket returns the next written packet, failing the test on timeout.
func (f *fakeTUN) waitPacket(t *testing.T, timeout time.Duration) []byte {
	t.Helper()
	select {
	case <-f.signal:
		return f.next()
	case <-time.After(timeout):
		t.Fatal("timed out waiting for TUN packet")
		return nil
	}
}

// waitPacketMatching returns the next written packet satisfying match, skipping
// non-matching ones (e.g. TCP retransmissions) until the timeout.
func (f *fakeTUN) waitPacketMatching(t *testing.T, timeout time.Duration, match func(pkt []byte) bool) []byte {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-f.signal:
			pkt := f.next()
			if match(pkt) {
				return pkt
			}
		case <-deadline:
			t.Fatal("timed out waiting for matching TUN packet")
			return nil
		}
	}
}

// fakeDialer dials nowhere: it records the requested address and hands back
// one end of a net.Pipe.
type fakeDialer struct {
	mu     sync.Mutex
	addrs  []string
	conns  []net.Conn
	signal chan struct{}
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{signal: make(chan struct{}, 16)}
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn1, conn2 := net.Pipe()
	d.mu.Lock()
	d.addrs = append(d.addrs, network+" "+address)
	d.conns = append(d.conns, conn1)
	d.mu.Unlock()
	d.signal <- struct{}{}
	return conn2, nil
}

// waitDial returns the last dialed "network address" string, failing the test
// on timeout.
func (d *fakeDialer) waitDial(t *testing.T, timeout time.Duration) string {
	t.Helper()
	select {
	case <-d.signal:
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.addrs[len(d.addrs)-1]
	case <-time.After(timeout):
		t.Fatal("timed out waiting for dial")
		return ""
	}
}

func (d *fakeDialer) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.addrs)
}

func newTestStack(t *testing.T, tun *fakeTUN, dialer *fakeDialer) *Stack {
	t.Helper()
	logger := nblog.NewFromLogrus(logrus.StandardLogger())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = logger.Stop(ctx)
	})

	s, err := New(tun, 1500, tunAddr, dialer.DialContext, logger)
	require.NoError(t, err)
	t.Cleanup(s.Stop)
	return s
}

// buildIPv4TCP assembles a full IPv4+TCP packet with valid checksums.
// header.*CalculateChecksum return the raw RFC 1071 sum, so the stored field
// is its complement.
func buildIPv4TCP(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16, flags header.TCPFlags, seq, ackNum uint32, window uint16, payload []byte) []byte {
	t.Helper()
	segLen := header.TCPMinimumSize + len(payload)
	buf := make([]byte, header.IPv4MinimumSize+segLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(header.TCPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
		Checksum:    0,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	tcpHdr := header.TCP(buf[header.IPv4MinimumSize:])
	copy(buf[header.IPv4MinimumSize+header.TCPMinimumSize:], payload)
	tcpHdr.Encode(&header.TCPFields{
		SrcPort:    srcPort,
		DstPort:    dstPort,
		SeqNum:     seq,
		AckNum:     ackNum,
		DataOffset: header.TCPMinimumSize,
		Flags:      flags,
		WindowSize: window,
		Checksum:   0,
	})
	pseudoSum := header.PseudoHeaderChecksum(header.TCPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(segLen))
	xsum := checksum.Combine(pseudoSum, checksum.Checksum(payload, 0))
	tcpHdr.SetChecksum(^tcpHdr.CalculateChecksum(xsum))

	return buf
}

// buildIPv4UDP assembles a full IPv4+UDP packet with valid checksums.
func buildIPv4UDP(t *testing.T, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	udpLen := header.UDPMinimumSize + len(payload)
	buf := make([]byte, header.IPv4MinimumSize+udpLen)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(header.UDPProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
		Checksum:    0,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	udpHdr := header.UDP(buf[header.IPv4MinimumSize:])
	copy(buf[header.IPv4MinimumSize+header.UDPMinimumSize:], payload)
	udpHdr.Encode(&header.UDPFields{
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Length:   uint16(udpLen),
		Checksum: 0,
	})
	pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, ip.SourceAddress(), ip.DestinationAddress(), uint16(udpLen))
	xsum := checksum.Combine(pseudoSum, checksum.Checksum(payload, 0))
	udpHdr.SetChecksum(^udpHdr.CalculateChecksum(xsum))

	return buf
}

// buildIPv4ICMP assembles an IPv4 ICMP echo request.
func buildIPv4ICMP(t *testing.T, src, dst netip.Addr) []byte {
	t.Helper()
	buf := make([]byte, header.IPv4MinimumSize+header.ICMPv4MinimumSize)

	ip := header.IPv4(buf)
	ip.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(buf)),
		TTL:         64,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     tcpip.AddrFrom4(src.As4()),
		DstAddr:     tcpip.AddrFrom4(dst.As4()),
		Checksum:    0,
	})
	ip.SetChecksum(^ip.CalculateChecksum())

	icmp := header.ICMPv4(buf[header.IPv4MinimumSize:])
	icmp.SetType(header.ICMPv4Echo)
	icmp.SetCode(0)
	icmp.SetChecksum(0)
	icmp.SetChecksum(^checksum.Checksum(icmp, 0))

	return buf
}

type parsedTCP struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
	flags            header.TCPFlags
	seq, ackNum      uint32
	payload          []byte
}

func parseIPv4TCP(t *testing.T, pkt []byte) parsedTCP {
	t.Helper()
	require.GreaterOrEqual(t, len(pkt), header.IPv4MinimumSize+header.TCPMinimumSize)

	ip := header.IPv4(pkt)
	require.Equal(t, uint8(header.TCPProtocolNumber), ip.Protocol())

	srcAddr := netip.AddrFrom4(ip.SourceAddress().As4())
	dstAddr := netip.AddrFrom4(ip.DestinationAddress().As4())

	tcpHdr := header.TCP(pkt[ip.HeaderLength():])
	hdrLen := int(tcpHdr.DataOffset())
	var payload []byte
	if len(tcpHdr) > hdrLen {
		payload = make([]byte, len(tcpHdr)-hdrLen)
		copy(payload, tcpHdr[hdrLen:])
	}

	return parsedTCP{
		src:     srcAddr,
		dst:     dstAddr,
		srcPort: tcpHdr.SourcePort(),
		dstPort: tcpHdr.DestinationPort(),
		flags:   tcpHdr.Flags(),
		seq:     tcpHdr.SequenceNumber(),
		ackNum:  tcpHdr.AckNumber(),
		payload: payload,
	}
}

// TestTCPHandshakeAndDataRelay injects a handcrafted SYN from a fake host
// application and verifies the full loop: dial to the right destination,
// SYN-ACK back to the host through the TUN writer, then payload relayed in
// both directions.
func TestTCPHandshakeAndDataRelay(t *testing.T) {
	tun := newFakeTUN()
	dialer := newFakeDialer()
	s := newTestStack(t, tun, dialer)

	const (
		clientPort = 12345
		remotePort = 443
	)
	clientISN := uint32(0x11111111)

	syn := buildIPv4TCP(t, clientAddr, remoteAddr, clientPort, remotePort, header.TCPFlagSyn, clientISN, 0, 65535, nil)
	require.NoError(t, s.Inject(syn))

	// The stack dials the application's destination, not the host.
	require.Equal(t, "tcp "+net.JoinHostPort(remoteAddr.String(), "443"), dialer.waitDial(t, 3*time.Second))
	require.Equal(t, 1, dialer.count())

	// gVisor answers the host through the TUN writer.
	synAckPkt := tun.waitPacket(t, 3*time.Second)
	synAck := parseIPv4TCP(t, synAckPkt)
	require.Equal(t, remoteAddr, synAck.src)
	require.Equal(t, clientAddr, synAck.dst)
	require.EqualValues(t, remotePort, synAck.srcPort)
	require.EqualValues(t, clientPort, synAck.dstPort)
	require.True(t, synAck.flags.Contains(header.TCPFlagSyn|header.TCPFlagAck), "expected SYN-ACK, got %v", synAck.flags)
	require.Equal(t, clientISN+1, synAck.ackNum)
	serverISN := synAck.seq

	outConn := dialer.conns[0]

	// Complete the handshake and send application data.
	require.NoError(t, s.Inject(buildIPv4TCP(t, clientAddr, remoteAddr, clientPort, remotePort, header.TCPFlagAck, clientISN+1, serverISN+1, 65535, nil)))

	payload := []byte("hello-bypass")
	require.NoError(t, s.Inject(buildIPv4TCP(t, clientAddr, remoteAddr, clientPort, remotePort, header.TCPFlagAck|header.TCPFlagPsh, clientISN+1, serverISN+1, 65535, payload)))

	require.NoError(t, outConn.SetReadDeadline(time.Now().Add(3*time.Second)))
	got := make([]byte, len(payload))
	_, err := io.ReadFull(outConn, got)
	require.NoError(t, err)
	require.Equal(t, payload, got)

	// Reverse direction: data from the dialed connection reaches the host as
	// a TUN packet addressed to the application's port.
	answer := []byte("world")
	_, err = outConn.Write(answer)
	require.NoError(t, err)

	answerPkt := tun.waitPacketMatching(t, 3*time.Second, func(pkt []byte) bool {
		p := parseIPv4TCP(t, pkt)
		return p.dstPort == clientPort && len(p.payload) == len(answer)
	})
	parsed := parseIPv4TCP(t, answerPkt)
	require.Equal(t, clientAddr, parsed.dst)
	require.Equal(t, answer, parsed.payload)
}

// TestUDPInjectDialsAndEchoes verifies the UDP path end to end: the injected
// datagram dials the right address, its payload reaches the dialed connection
// and a response from there comes back as a TUN packet to the host.
func TestUDPInjectDialsAndEchoes(t *testing.T) {
	tun := newFakeTUN()
	dialer := newFakeDialer()
	s := newTestStack(t, tun, dialer)

	const (
		clientPort = 54321
		remotePort = 53
	)

	query := []byte("query")
	require.NoError(t, s.Inject(buildIPv4UDP(t, clientAddr, dnsAddr, clientPort, remotePort, query)))

	require.Equal(t, "udp "+net.JoinHostPort(dnsAddr.String(), "53"), dialer.waitDial(t, 3*time.Second))

	outConn := dialer.conns[0]
	require.NoError(t, outConn.SetReadDeadline(time.Now().Add(3*time.Second)))
	got := make([]byte, len(query))
	_, err := io.ReadFull(outConn, got)
	require.NoError(t, err)
	require.Equal(t, query, got)

	answer := []byte("answer")
	_, err = outConn.Write(answer)
	require.NoError(t, err)

	answerPkt := tun.waitPacketMatching(t, 3*time.Second, func(pkt []byte) bool {
		return len(pkt) == header.IPv4MinimumSize+header.UDPMinimumSize+len(answer)
	})
	ip := header.IPv4(answerPkt)
	require.Equal(t, dnsAddr.String(), ip.SourceAddress().String())
	require.Equal(t, clientAddr.String(), ip.DestinationAddress().String())
	udpHdr := header.UDP(answerPkt[ip.HeaderLength():])
	require.EqualValues(t, remotePort, udpHdr.SourcePort())
	require.EqualValues(t, clientPort, udpHdr.DestinationPort())
	require.Equal(t, answer, []byte(udpHdr.Payload()))
}

// TestInjectValidation checks argument handling and the v1 ICMP drop: ICMP
// must neither dial nor produce TUN packets.
func TestInjectValidation(t *testing.T) {
	tun := newFakeTUN()
	dialer := newFakeDialer()
	s := newTestStack(t, tun, dialer)

	require.Error(t, s.Inject(nil))
	require.Error(t, s.Inject([]byte{0x45, 0x00})) // IPv4 but too small
	require.Error(t, s.Inject([]byte{0x30, 0x00, 0x00, 0x00}))

	require.NoError(t, s.Inject(buildIPv4ICMP(t, clientAddr, remoteAddr)))

	// Nothing may be dialed or written back for ICMP.
	select {
	case <-tun.signal:
		t.Fatalf("unexpected TUN packet for dropped ICMP: %x", tun.next())
	case <-time.After(300 * time.Millisecond):
	}
	require.Equal(t, 0, dialer.count())
	require.Equal(t, 0, tun.count())
}
