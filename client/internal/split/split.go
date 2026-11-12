// Package split implements the decision core of the per-app split tunnel.
// It maps a connection to its owning application and decides whether the
// traffic flows through the regular NetBird tunnel or bypasses it.
package split

import (
	"fmt"
	"slices"
	"strings"
)

// Mode selects how the app list of a Settings is interpreted.
type Mode int

const (
	// ModeOff disables splitting: all traffic takes the tunnel.
	ModeOff Mode = iota
	// ModeInclude tunnels only the listed apps; everything else bypasses.
	ModeInclude
	// ModeExclude tunnels everything except the listed apps, which bypass.
	ModeExclude
)

func (m Mode) String() string {
	switch m {
	case ModeInclude:
		return "include"
	case ModeExclude:
		return "exclude"
	default:
		return "off"
	}
}

// ParseMode parses a mode name as it appears in specs and the store file.
// Matching is case-insensitive.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ModeOff.String():
		return ModeOff, nil
	case ModeInclude.String():
		return ModeInclude, nil
	case ModeExclude.String():
		return ModeExclude, nil
	default:
		return ModeOff, fmt.Errorf("unknown split mode %q", s)
	}
}

// Settings is the split tunnel configuration. Apps holds executable base
// names (e.g. "opera.exe"), lower-cased, deduplicated and sorted. Settings
// is normalized by ParseSpec, LoadStore, NewEngine and Engine.Update.
type Settings struct {
	Mode Mode
	Apps []string
}

// Verdict is the engine decision for a single connection.
type Verdict int

const (
	// VerdictTunnel keeps the traffic on the regular NetBird tunnel path.
	VerdictTunnel Verdict = iota
	// VerdictBypass sends the traffic outside the tunnel via the bypass stack.
	VerdictBypass
)

// Protocol is the transport protocol of the connection the engine decides on.
type Protocol int

const (
	ProtoTCP Protocol = iota
	ProtoUDP
)

// normalizeApps lower-cases, trims, deduplicates and sorts app names, and
// returns a new slice that shares no backing storage with apps.
func normalizeApps(apps []string) []string {
	out := make([]string, 0, len(apps))
	seen := make(map[string]struct{}, len(apps))
	for _, app := range apps {
		app = strings.ToLower(strings.TrimSpace(app))
		if app == "" {
			continue
		}
		if _, dup := seen[app]; dup {
			continue
		}
		seen[app] = struct{}{}
		out = append(out, app)
	}
	slices.Sort(out)
	return out
}
