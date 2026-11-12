package uspfilter

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/bypass"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	nblog "github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/internal/split"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// bypassDialTimeout bounds a single bypass dial.
const bypassDialTimeout = 30 * time.Second

// SetSplitTunnel installs or removes the per-app split tunnel engine. ModeOff
// clears the engine (filterOutbound returns to its unchanged path) and stops
// the bypass stack. Any other mode installs a fresh engine with an empty
// verdict cache; the bypass stack, if running, is kept for the new settings.
//
// Splitting requires advanced routing: the bypass dialer binds its sockets to
// the physical interface only when advanced routing is enabled, and without
// that binding the re-originated traffic would loop back into the tunnel. In
// legacy routing and netstack modes the call therefore fails closed with an
// error and everything stays on the tunnel.
func (m *Manager) SetSplitTunnel(s split.Settings) error {
	if s.Mode == split.ModeOff {
		m.splitEngine.Store(nil)
		m.stopBypassStack()
		return nil
	}

	// Process attribution only exists on Windows; on any other platform the
	// noop classifier would silently tunnel everything while reporting the
	// split as active. Fail loudly instead, like the iptables/nftables stubs.
	if runtime.GOOS != "windows" {
		return fmt.Errorf("split tunnel is not implemented on %s", runtime.GOOS)
	}

	if !nbnet.AdvancedRouting() {
		return errors.New("split tunnel requires advanced routing, refusing to split (traffic stays on the tunnel)")
	}

	// The split package selects the real process classifier on Windows and a
	// noop (always-tunnel, fail-closed) one elsewhere.
	m.splitEngine.Store(split.NewEngine(s, split.NewProcessClassifier()))
	return nil
}

// SetSplitTunnelRoutes records the prefixes NetBird routes through the tunnel
// (network routes behind routing peers; catch-all exit node routes are
// excluded by the caller). Destinations inside these prefixes are NetBird
// resources and must never be captured by the split bypass, which dials
// outside the tunnel.
func (m *Manager) SetSplitTunnelRoutes(prefixes []netip.Prefix) error {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, func(a, b netip.Prefix) int {
		if cmp := a.Addr().Compare(b.Addr()); cmp != 0 {
			return cmp
		}
		return a.Bits() - b.Bits()
	})
	m.splitRoutes.Store(&sorted)
	return nil
}

// splitBypassOut consults the split tunnel engine for the connection and, on a
// bypass verdict, hands the packet to the bypass stack instead of the tunnel.
// It reports whether the packet was consumed by the bypass stack and must be
// dropped from the WireGuard path. With no engine installed it returns false
// immediately, so the regular path pays a single atomic load.
func (m *Manager) splitBypassOut(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, proto split.Protocol, packetData []byte) bool {
	eng := m.splitEngine.Load()
	if eng == nil {
		return false
	}

	// v1 splits IPv4 only; IPv6 stays on the tunnel (and the bypass stack is
	// given a single NIC address).
	if !dstIP.Is4() {
		return false
	}

	key := conntrack.ConnKey{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// Overlay destinations always take the tunnel.
	if m.dstInOverlay(dstIP) {
		return false
	}

	verdict, owner := eng.Decide(key, proto)
	if verdict == split.VerdictTunnel {
		return false
	}

	if m.logger.Enabled(nblog.LevelTrace) {
		m.logger.Trace2("split: bypassing %s connection %s", owner, key.String())
	}

	stack, err := m.ensureBypassStack()
	if err != nil {
		log.Warnf("split: bypass stack unavailable, tunneling instead: %v", err)
		return false
	}
	if err := stack.Inject(packetData); err != nil {
		log.Warnf("split: inject into bypass stack failed, tunneling instead: %v", err)
		return false
	}

	return true
}

// dstInOverlay reports whether dstIP is served by the NetBird tunnel: either
// the overlay networks themselves (the v4 network and, if assigned, the v6
// one) or one of the routed networks registered via SetSplitTunnelRoutes.
func (m *Manager) dstInOverlay(dstIP netip.Addr) bool {
	if m.wgIface.Address().Network.Contains(dstIP) {
		return true
	}
	if v6 := m.wgIface.Address().IPv6Net; v6.IsValid() && v6.Contains(dstIP) {
		return true
	}
	if routes := m.splitRoutes.Load(); routes != nil {
		for _, prefix := range *routes {
			if prefix.Contains(dstIP) {
				return true
			}
		}
	}
	return false
}

// ensureBypassStack returns the bypass stack, creating it lazily on the first
// bypass verdict. Creation failures are not cached: the next bypass verdict
// retries, and until then traffic tunnels (fail-closed).
func (m *Manager) ensureBypassStack() (*bypass.Stack, error) {
	if s := m.bypassStack.Load(); s != nil {
		return s, nil
	}

	m.bypassMu.Lock()
	defer m.bypassMu.Unlock()

	if s := m.bypassStack.Load(); s != nil {
		return s, nil
	}
	// The split tunnel may have been switched off while this flow was being
	// decided on a stale engine; don't resurrect the stack behind it.
	if m.splitEngine.Load() == nil {
		return nil, errors.New("split tunnel is off")
	}

	tun := m.wgIface.Tun()
	if tun == nil {
		return nil, errors.New("no TUN device to write bypass answers to")
	}

	stack, err := bypass.New(tun, m.mtu, m.wgIface.Address().IP, m.newBypassDialerFn(), m.logger)
	if err != nil {
		return nil, fmt.Errorf("create bypass stack: %w", err)
	}

	m.bypassStack.Store(stack)
	log.Debug("split: bypass stack created")
	return stack, nil
}

// stopBypassStack stops and clears the bypass stack if one was created.
func (m *Manager) stopBypassStack() {
	m.bypassMu.Lock()
	defer m.bypassMu.Unlock()

	if s := m.bypassStack.Swap(nil); s != nil {
		s.Stop()
		log.Debug("split: bypass stack stopped")
	}
}
