package bypass

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

// endpoint implements stack.LinkEndpoint. It hands the packets gVisor
// produces back to the host by writing full IP packets into the TUN device,
// mirroring the dns/tcpstack.go pattern.
type endpoint struct {
	logger     *nblog.Logger
	tun        TUNWriter
	dispatcher stack.NetworkDispatcher
	mtu        atomic.Uint32
}

func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher
}

func (e *endpoint) IsAttached() bool {
	return e.dispatcher != nil
}

func (e *endpoint) MTU() uint32 {
	return e.mtu.Load()
}

func (e *endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (e *endpoint) MaxHeaderLength() uint16 {
	return 0
}

func (e *endpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (e *endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	var written int
	for _, pkt := range pkts.AsSlice() {
		data := stack.PayloadSince(pkt.NetworkHeader())
		if data == nil {
			continue
		}

		raw := data.AsSlice()
		_, err := e.tun.Write([][]byte{raw}, 0)
		data.Release()
		if err != nil {
			e.logger.Error1("bypass: tun write error: %v", err)
			continue
		}
		written++
	}

	return written, nil
}

func (e *endpoint) Wait() {
	// not required
}

func (e *endpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (e *endpoint) AddHeader(*stack.PacketBuffer) {
	// not required
}

func (e *endpoint) ParseHeader(*stack.PacketBuffer) bool {
	return true
}

func (e *endpoint) Close() {
	// Endpoint cleanup - nothing to do as TUN device is managed externally
}

func (e *endpoint) SetLinkAddress(tcpip.LinkAddress) {
	// Link address is not used for this endpoint type
}

func (e *endpoint) SetMTU(mtu uint32) {
	e.mtu.Store(mtu)
}

func (e *endpoint) SetOnCloseAction(func()) {
	// No action needed on close
}
