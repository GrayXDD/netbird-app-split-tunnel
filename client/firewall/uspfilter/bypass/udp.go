package bypass

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
)

const (
	udpTimeout = 30 * time.Second
)

type udpPacketConn struct {
	conn     *gonet.UDPConn
	outConn  net.Conn
	lastSeen atomic.Int64
	cancel   context.CancelFunc
	ep       tcpip.Endpoint
}

type udpForwarder struct {
	sync.RWMutex
	logger  *nblog.Logger
	conns   map[stack.TransportEndpointID]*udpPacketConn
	bufPool sync.Pool
	ctx     context.Context
	cancel  context.CancelFunc
}

type idleConn struct {
	id   stack.TransportEndpointID
	conn *udpPacketConn
}

func newUDPForwarder(mtu uint16, logger *nblog.Logger, parentCtx context.Context) *udpForwarder {
	ctx, cancel := context.WithCancel(parentCtx)
	f := &udpForwarder{
		logger: logger,
		conns:  make(map[stack.TransportEndpointID]*udpPacketConn),
		ctx:    ctx,
		cancel: cancel,
		bufPool: sync.Pool{
			New: func() any {
				b := make([]byte, mtu)
				return &b
			},
		},
	}
	go f.cleanup()
	return f
}

// Stop stops the UDP forwarder and all active connections
func (f *udpForwarder) Stop() {
	f.cancel()

	f.Lock()
	defer f.Unlock()

	for id, conn := range f.conns {
		conn.cancel()
		if err := conn.conn.Close(); err != nil {
			f.logger.Debug2("bypass: UDP conn close error for %v: %v", epID(id), err)
		}
		if err := conn.outConn.Close(); err != nil {
			f.logger.Debug2("bypass: UDP outConn close error for %v: %v", epID(id), err)
		}

		conn.ep.Close()
		delete(f.conns, id)
	}
}

// cleanup periodically removes idle UDP connections
func (f *udpForwarder) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			var idleConns []idleConn

			f.RLock()
			for id, conn := range f.conns {
				if conn.getIdleDuration() > udpTimeout {
					idleConns = append(idleConns, idleConn{id, conn})
				}
			}
			f.RUnlock()

			for _, idle := range idleConns {
				idle.conn.cancel()
				if err := idle.conn.conn.Close(); err != nil {
					f.logger.Debug2("bypass: UDP conn close error for %v: %v", epID(idle.id), err)
				}
				if err := idle.conn.outConn.Close(); err != nil {
					f.logger.Debug2("bypass: UDP outConn close error for %v: %v", epID(idle.id), err)
				}

				idle.conn.ep.Close()

				f.Lock()
				delete(f.conns, idle.id)
				f.Unlock()

				if f.logger.Enabled(nblog.LevelTrace) {
					f.logger.Trace1("bypass: cleaned up idle UDP connection %v", epID(idle.id))
				}
			}
		}
	}
}

// handleUDP is called by the UDP forwarder for new packets. id.Local
// address/port are the destination the host application addressed; the
// datagram is re-originated there through the stack's dial function.
func (s *Stack) handleUDP(r *udp.ForwarderRequest) bool {
	if s.ctx.Err() != nil {
		s.logger.Trace("bypass: context done, dropping UDP packet")
		return false
	}

	id := r.ID()

	s.udpFwd.RLock()
	_, exists := s.udpFwd.conns[id]
	s.udpFwd.RUnlock()
	if exists {
		if s.logger.Enabled(nblog.LevelTrace) {
			s.logger.Trace1("bypass: existing UDP connection for %v", epID(id))
		}
		return true
	}

	dstAddr := net.JoinHostPort(addrToNetipAddr(id.LocalAddress).String(), strconv.Itoa(int(id.LocalPort)))
	outConn, err := s.dial(s.ctx, "udp", dstAddr)
	if err != nil {
		s.logger.Debug2("bypass: UDP dial error for %v: %v", epID(id), err)
		// TODO: Send ICMP error message
		return false
	}

	// Create wait queue for blocking syscalls
	wq := waiter.Queue{}
	ep, epErr := r.CreateEndpoint(&wq)
	if epErr != nil {
		s.logger.Debug1("bypass: failed to create UDP endpoint: %v", epErr)
		if err := outConn.Close(); err != nil {
			s.logger.Debug2("bypass: UDP outConn close error for %v: %v", epID(id), err)
		}
		return false
	}

	inConn := gonet.NewUDPConn(&wq, ep)
	connCtx, connCancel := context.WithCancel(s.ctx)

	pConn := &udpPacketConn{
		conn:    inConn,
		outConn: outConn,
		cancel:  connCancel,
		ep:      ep,
	}
	pConn.updateLastSeen()

	s.udpFwd.Lock()
	// Double-check no connection was created while we were setting up
	if _, exists := s.udpFwd.conns[id]; exists {
		s.udpFwd.Unlock()
		pConn.cancel()
		if err := inConn.Close(); err != nil {
			s.logger.Debug2("bypass: UDP inConn close error for %v: %v", epID(id), err)
		}
		if err := outConn.Close(); err != nil {
			s.logger.Debug2("bypass: UDP outConn close error for %v: %v", epID(id), err)
		}
		return true
	}
	s.udpFwd.conns[id] = pConn
	s.udpFwd.Unlock()

	if s.logger.Enabled(nblog.LevelTrace) {
		s.logger.Trace1("bypass: established UDP connection %v", epID(id))
	}

	go s.proxyUDP(connCtx, pConn, id, ep)
	return true
}

func (s *Stack) proxyUDP(ctx context.Context, pConn *udpPacketConn, id stack.TransportEndpointID, ep tcpip.Endpoint) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		<-ctx.Done()

		pConn.cancel()
		if err := pConn.conn.Close(); err != nil && !isClosedError(err) {
			s.logger.Debug2("bypass: UDP inConn close error for %v: %v", epID(id), err)
		}
		if err := pConn.outConn.Close(); err != nil && !isClosedError(err) {
			s.logger.Debug2("bypass: UDP outConn close error for %v: %v", epID(id), err)
		}

		ep.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	var txBytes, rxBytes int64
	var outboundErr, inboundErr error

	// outbound->inbound: copy from pConn.conn to pConn.outConn
	go func() {
		defer wg.Done()
		txBytes, outboundErr = pConn.copy(ctx, pConn.conn, pConn.outConn, &s.udpFwd.bufPool, "outbound->inbound")
	}()

	// inbound->outbound: copy from pConn.outConn to pConn.conn
	go func() {
		defer wg.Done()
		rxBytes, inboundErr = pConn.copy(ctx, pConn.outConn, pConn.conn, &s.udpFwd.bufPool, "inbound->outbound")
	}()

	wg.Wait()

	if outboundErr != nil && !isClosedError(outboundErr) {
		s.logger.Error2("proxyUDP: copy error (outbound→inbound) for %s: %v", epID(id), outboundErr)
	}
	if inboundErr != nil && !isClosedError(inboundErr) {
		s.logger.Error2("proxyUDP: copy error (inbound→outbound) for %s: %v", epID(id), inboundErr)
	}

	s.udpFwd.Lock()
	delete(s.udpFwd.conns, id)
	s.udpFwd.Unlock()

	if s.logger.Enabled(nblog.LevelTrace) {
		s.logger.Trace3("bypass: removed UDP connection %s [in: %d B, out: %d B]", epID(id), rxBytes, txBytes)
	}
}

func (c *udpPacketConn) updateLastSeen() {
	c.lastSeen.Store(time.Now().UnixNano())
}

func (c *udpPacketConn) getIdleDuration() time.Duration {
	lastSeen := time.Unix(0, c.lastSeen.Load())
	return time.Since(lastSeen)
}

// copy reads from src and writes to dst.
func (c *udpPacketConn) copy(ctx context.Context, dst net.Conn, src net.Conn, bufPool *sync.Pool, direction string) (int64, error) {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buffer := *bufp
	var totalBytes int64 = 0

	for {
		if ctx.Err() != nil {
			return totalBytes, ctx.Err()
		}

		if err := src.SetDeadline(time.Now().Add(udpTimeout)); err != nil {
			return totalBytes, fmt.Errorf("set read deadline: %w", err)
		}

		n, err := src.Read(buffer)
		if err != nil {
			if isTimeout(err) {
				continue
			}
			return totalBytes, fmt.Errorf("read from %s: %w", direction, err)
		}

		nWritten, err := dst.Write(buffer[:n])
		if err != nil {
			return totalBytes, fmt.Errorf("write to %s: %w", direction, err)
		}

		totalBytes += int64(nWritten)
		c.updateLastSeen()
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, io.EOF)
}

func isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}
