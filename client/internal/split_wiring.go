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
// on the common path of the daemon and one-off runs, and on hot setting
// changes via ApplySplitTunnelNow. Failures are logged and never abort the
// connection: an unsupported backend or an apply error leaves the tunnel
// carrying all traffic.
func (e *Engine) applySplitTunnel() {
	cfg := e.config.SplitTunnel
	if cfg == nil {
		return
	}

	// An off mode still reaches a live firewall: SetSplitTunnel(ModeOff)
	// clears a previously installed engine, so a hot switch to off takes
	// effect immediately instead of surviving until the next start.
	if cfg.Mode == split.ModeOff {
		if e.firewall != nil {
			if err := e.firewall.SetSplitTunnel(*cfg); err != nil {
				log.Warnf("split tunnel: failed to disable splitting: %v", err)
			}
		}
		return
	}

	if e.firewall == nil {
		return
	}

	if err := e.firewall.SetSplitTunnel(*cfg); err != nil {
		log.Warnf("split tunnel: failed to apply settings, splitting stays off: %v", err)
		return
	}

	e.syncSplitTunnelRoutes()

	log.Infof("split tunnel: mode %s, apps: %s", cfg.Mode, strings.Join(cfg.Apps, ", "))
}

// ApplySplitTunnelNow hot-applies new split tunnel settings to a running
// engine: the settings replace the engine config and are pushed to the live
// firewall manager, so a mode or app list change takes effect without a
// reconnect; a switch to ModeOff clears an installed engine immediately. When
// the engine has no firewall manager (still starting, or the firewall is
// disabled) the settings are only stored in the config and take effect on the
// next start.
//
// The call takes syncMsgMux, serializing against Management syncs (which
// refresh the split tunnel routes under the same lock) and against engine
// teardown in Stop, so the firewall manager cannot be torn down mid-apply.
func (e *Engine) ApplySplitTunnelNow(s split.Settings) {
	e.syncMsgMux.Lock()
	defer e.syncMsgMux.Unlock()

	e.config.SplitTunnel = &s
	e.applySplitTunnel()
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
