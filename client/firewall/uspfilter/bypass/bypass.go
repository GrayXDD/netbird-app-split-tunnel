// Package bypass terminates host outbound traffic in a userspace gVisor stack
// and re-originates it through a caller-provided dialer.
//
// It is a variant of uspfilter/forwarder used for split tunneling: packets
// intercepted on the way to the tunnel are injected here, TCP/UDP are
// terminated locally, and the answer packets gVisor produces are written back
// to the host through the TUN device instead of the WireGuard device. All
// outbound connections are dialed exclusively through the DialContextFunc
// passed to New; dialing with a bare net.Dialer would loop the traffic back
// into the tunnel.
package bypass

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

const (
	defaultReceiveWindow = 32768
	defaultMaxInFlight   = 1024

	// envForceTCPRACK mirrors forwarder's override for gVisor's RACK loss
	// detection so both stacks behave identically in the same process.
	envForceTCPRACK = "NB_FORCE_TCP_RACK"
)

// TUNWriter is the packet sink for answers produced by the stack. It matches
// the write side of wireguard-go's tun.Device: each bufs[i][offset:] is one
// full IP packet handed back to the host.
type TUNWriter interface {
	Write(bufs [][]byte, offset int) (int, error)
}

// DialContextFunc dials an outbound connection for terminated traffic. The
// implementation must bind sockets outside the tunnel interface, otherwise
// bypassed traffic loops back through the tunnel.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// Stack terminates injected host traffic and re-originates it via dial.
type Stack struct {
	logger   *nblog.Logger
	dial     DialContextFunc
	stack    *stack.Stack
	endpoint *endpoint
	udpFwd   *udpForwarder
	ctx      context.Context
	cancel   context.CancelFunc
}

// New creates the bypass stack. tun receives the answer packets gVisor
// produces for the host. addr is the tunnel interface address (wt0): gVisor
// needs it assigned to the NIC so TCP handshakes with the host's tunnel
// address can be answered. dial dials every outbound connection; it must bind
// outside the tunnel or traffic loops.
func New(tun TUNWriter, mtu uint16, addr netip.Addr, dial DialContextFunc, logger *nblog.Logger) (*Stack, error) {
	if tun == nil {
		return nil, errors.New("bypass: TUN writer is required")
	}
	if dial == nil {
		return nil, errors.New("bypass: dial function is required")
	}
	if !addr.IsValid() {
		return nil, errors.New("bypass: tunnel address is required")
	}

	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
		HandleLocal: false,
	})

	nicID := tcpip.NICID(1)
	ep := &endpoint{
		logger: logger,
		tun:    tun,
	}
	ep.mtu.Store(uint32(mtu))

	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create NIC: %v", err)
	}

	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(addr.As4()),
			PrefixLen: 32,
		},
	}
	if addr.Is6() {
		protoAddr.Protocol = ipv6.ProtocolNumber
		protoAddr.AddressWithPrefix = tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16(addr.As16()),
			PrefixLen: 128,
		}
	}
	if err := s.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add protocol address: %s", err)
	}

	defaultSubnet, err := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFromBytes([]byte{0, 0, 0, 0}),
	)
	if err != nil {
		return nil, fmt.Errorf("creating default subnet: %w", err)
	}

	defaultSubnetV6, err := tcpip.NewSubnet(
		tcpip.AddrFrom16([16]byte{}),
		tcpip.MaskFromBytes(make([]byte, 16)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating default v6 subnet: %w", err)
	}

	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("set promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("set spoofing: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{Destination: defaultSubnet, NIC: nicID},
		{Destination: defaultSubnetV6, NIC: nicID},
	})

	ctx, cancel := context.WithCancel(context.Background())
	bs := &Stack{
		logger:   logger,
		dial:     dial,
		stack:    s,
		endpoint: ep,
		udpFwd:   newUDPForwarder(mtu, logger, ctx),
		ctx:      ctx,
		cancel:   cancel,
	}

	configureTCPRecovery(s)

	tcpForwarder := tcp.NewForwarder(s, defaultReceiveWindow, defaultMaxInFlight, bs.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)

	udpForwarder := udp.NewForwarder(s, bs.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	// Inject drops ICMP before it reaches gVisor (v1: ICMP stays on the
	// tunnel path), so no ICMP transport handler is wired here.

	log.Debugf("bypass: initialization complete with NIC %d", nicID)
	return bs, nil
}

// Inject delivers an intercepted outbound IP packet into the stack. ICMP
// packets are dropped (v1 keeps ICMP on the tunnel path). packetData may be a
// reused buffer; the stack copies the bytes.
func (s *Stack) Inject(packetData []byte) error {
	if len(packetData) == 0 {
		return errors.New("empty packet")
	}

	var protoNum tcpip.NetworkProtocolNumber
	switch packetData[0] >> 4 {
	case 4:
		if len(packetData) < header.IPv4MinimumSize {
			return fmt.Errorf("IPv4 packet too small: %d bytes", len(packetData))
		}
		if header.IPv4(packetData).Protocol() == uint8(header.ICMPv4ProtocolNumber) {
			if s.logger.Enabled(nblog.LevelTrace) {
				s.logger.Trace("bypass: dropping ICMPv4 packet, ICMP stays on the tunnel path")
			}
			return nil
		}
		protoNum = ipv4.ProtocolNumber
	case 6:
		if len(packetData) < header.IPv6MinimumSize {
			return fmt.Errorf("IPv6 packet too small: %d bytes", len(packetData))
		}
		if header.IPv6(packetData).NextHeader() == uint8(header.ICMPv6ProtocolNumber) {
			if s.logger.Enabled(nblog.LevelTrace) {
				s.logger.Trace("bypass: dropping ICMPv6 packet, ICMP stays on the tunnel path")
			}
			return nil
		}
		protoNum = ipv6.ProtocolNumber
	default:
		return fmt.Errorf("unknown IP version: %d", packetData[0]>>4)
	}

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(packetData),
	})
	defer pkt.DecRef()

	if s.endpoint.dispatcher == nil {
		return errors.New("bypass stack is not attached")
	}
	s.endpoint.dispatcher.DeliverNetworkPacket(protoNum, pkt)
	return nil
}

// Stop gracefully shuts down the stack.
func (s *Stack) Stop() {
	s.cancel()

	if s.udpFwd != nil {
		s.udpFwd.Stop()
	}

	s.stack.Close()
	s.stack.Wait()
}

// configureTCPRecovery disables gVisor's RACK loss detection on Windows, where
// it interacts poorly with the host and collapses throughput on routed TCP
// connections (gVisor issue #9778). Other platforms keep the default. The
// envForceTCPRACK environment variable overrides the platform default.
// Mirrors forwarder.configureTCPRecovery.
func configureTCPRecovery(s *stack.Stack) {
	disableRACK := runtime.GOOS == "windows"

	if val := os.Getenv(envForceTCPRACK); val != "" {
		force, err := strconv.ParseBool(val)
		if err != nil {
			log.Warnf("parse %s: %v", envForceTCPRACK, err)
		} else {
			disableRACK = !force
		}
	}

	if !disableRACK {
		return
	}

	opt := tcpip.TCPRecovery(0)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &opt); err != nil {
		log.Warnf("disable TCP RACK loss detection: %v", err)
		return
	}
	log.Info("bypass: TCP RACK loss detection disabled")
}

// addrToNetipAddr converts a gvisor tcpip.Address to netip.Addr without allocating.
func addrToNetipAddr(addr tcpip.Address) netip.Addr {
	switch addr.Len() {
	case 4:
		return netip.AddrFrom4(addr.As4())
	case 16:
		return netip.AddrFrom16(addr.As16())
	default:
		return netip.Addr{}
	}
}

type epID stack.TransportEndpointID

func (i epID) String() string {
	// src and remote is swapped
	return net.JoinHostPort(i.RemoteAddress.String(), strconv.Itoa(int(i.RemotePort))) +
		" → " +
		net.JoinHostPort(i.LocalAddress.String(), strconv.Itoa(int(i.LocalPort)))
}
