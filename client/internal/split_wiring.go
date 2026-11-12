package internal

import (
	"net/netip"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/split"
	"github.com/netbirdio/netbird/route"
)

// SplitTunnelEnv names the environment variable holding a per-app split
// tunnel spec ("<mode>:<app>[,<app>...]", e.g. "include:opera.exe,telegram.exe").
// When set and valid it overrides the split.json store in the config dir.
const SplitTunnelEnv = "NB_SPLIT_TUNNEL"

// resolveSplitSettings resolves the split tunnel settings for a connection:
// the NB_SPLIT_TUNNEL environment variable wins over the split.json store in
// configDir, and a missing store yields the default (off). Invalid input is
// logged and degrades to off instead of failing the connection, so a broken
// setting can never take the tunnel down with it.
func resolveSplitSettings(configDir string) (split.Settings, error) {
	if spec := os.Getenv(SplitTunnelEnv); spec != "" {
		settings, err := split.ParseSpec(spec)
		if err != nil {
			log.Warnf("split tunnel: ignoring invalid %s value: %v", SplitTunnelEnv, err)
			return split.Settings{Mode: split.ModeOff}, nil
		}
		return settings, nil
	}

	settings, err := split.LoadStore(configDir)
	if err != nil {
		log.Warnf("split tunnel: ignoring unreadable store in %s: %v", configDir, err)
		return split.Settings{Mode: split.ModeOff}, nil
	}
	return settings, nil
}

// applySplitTunnel pushes the resolved split tunnel settings into the firewall
// backend. It runs on engine start right after the firewall manager is created,
// on the common path of the daemon and one-off runs. Failures are logged and
// never abort the connection: an unsupported backend or an apply error leaves
// the tunnel carrying all traffic.
func (e *Engine) applySplitTunnel() {
	cfg := e.config.SplitTunnel
	if cfg == nil || cfg.Mode == split.ModeOff {
		return
	}

	if err := e.firewall.SetSplitTunnel(*cfg); err != nil {
		log.Warnf("split tunnel: failed to apply settings, splitting stays off: %v", err)
		return
	}

	e.syncSplitTunnelRoutes()

	log.Infof("split tunnel: mode %s, apps: %s", cfg.Mode, strings.Join(cfg.Apps, ", "))
}

// syncSplitTunnelRoutes tells the firewall backend which prefixes NetBird
// routes through the tunnel, so the split bypass never captures traffic to
// routed corporate networks. It runs when the split is applied and again
// whenever management updates the routes.
func (e *Engine) syncSplitTunnelRoutes() {
	if e.firewall == nil || e.routeManager == nil {
		return
	}
	cfg := e.config.SplitTunnel
	if cfg == nil || cfg.Mode == split.ModeOff {
		return
	}

	if err := e.firewall.SetSplitTunnelRoutes(splitTunnelRoutePrefixes(e.routeManager.GetSelectedClientRoutes())); err != nil {
		log.Warnf("split tunnel: failed to register routed networks, routed traffic may bypass the tunnel: %v", err)
	}
}

// splitTunnelRoutePrefixes returns the network prefixes of the client routes
// that must stay on the tunnel. Catch-all prefixes (0.0.0.0/0, ::/0, the exit
// node default) are excluded: they cover everything and are exactly the
// traffic the split tunnel divides per app. DNS routes carry domains instead
// of a network and yield no prefix.
func splitTunnelRoutePrefixes(routes route.HAMap) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, group := range routes {
		for _, r := range group {
			if !r.Network.IsValid() || r.Network.Bits() == 0 {
				continue
			}
			prefixes = append(prefixes, r.Network)
		}
	}
	return prefixes
}
