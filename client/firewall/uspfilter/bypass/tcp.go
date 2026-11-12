package bypass

import (
	"net"
	"strconv"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/util/netrelay"
)

// handleTCP is called by the TCP forwarder for new connections. id.Local
// address/port are the destination the host application addressed; the
// connection is re-originated there through the stack's dial function.
func (s *Stack) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()

	dialAddr := net.JoinHostPort(addrToNetipAddr(id.LocalAddress).String(), strconv.Itoa(int(id.LocalPort)))

	outConn, err := s.dial(s.ctx, "tcp", dialAddr)
	if err != nil {
		r.Complete(true)
		if s.logger.Enabled(nblog.LevelTrace) {
			s.logger.Trace2("bypass: dial error for %v: %v", epID(id), err)
		}
		return
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}

	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		s.logger.Error1("bypass: failed to create TCP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			s.logger.Debug1("bypass: outConn close error: %v", err)
		}
		r.Complete(true)
		return
	}

	// Complete the handshake
	r.Complete(false)

	inConn := gonet.NewTCPConn(&wq, ep)

	if s.logger.Enabled(nblog.LevelTrace) {
		s.logger.Trace1("bypass: established TCP connection %v", epID(id))
	}

	go s.proxyTCP(id, inConn, outConn, ep)
}

func (s *Stack) proxyTCP(id stack.TransportEndpointID, inConn *gonet.TCPConn, outConn net.Conn, ep tcpip.Endpoint) {
	// netrelay.Relay copies bidirectionally with proper half-close propagation
	// and fully closes both conns before returning.
	bytesFromInToOut, bytesFromOutToIn := netrelay.Relay(s.ctx, inConn, outConn, netrelay.Options{
		Logger: s.logger,
	})

	// Close the netstack endpoint after both conns are drained.
	ep.Close()

	if s.logger.Enabled(nblog.LevelTrace) {
		s.logger.Trace3("bypass: removed TCP connection %s [in: %d B, out: %d B]", epID(id), bytesFromOutToIn, bytesFromInToOut)
	}
}
