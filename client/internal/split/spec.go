package split

import (
	"fmt"
	"strings"
)

// ParseSpec parses a spec of the form "<mode>:<app>[,<app>...]" — e.g.
// "include:opera.exe,telegram.exe" — into settings. An empty spec, or the
// bare mode "off", yields ModeOff with no apps. Unknown modes and empty app
// entries are errors.
func ParseSpec(spec string) (Settings, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return Settings{Mode: ModeOff}, nil
	}

	modePart, appsPart, ok := strings.Cut(spec, ":")
	mode, err := ParseMode(modePart)
	if err != nil {
		return Settings{}, fmt.Errorf("invalid split spec %q: %w", spec, err)
	}
	if !ok {
		if mode == ModeOff {
			return Settings{Mode: ModeOff}, nil
		}
		return Settings{}, fmt.Errorf("invalid split spec %q: expected <mode>:<apps>", spec)
	}

	apps := make([]string, 0, len(appsPart))
	for _, app := range strings.Split(appsPart, ",") {
		app = strings.ToLower(strings.TrimSpace(app))
		if app == "" {
			return Settings{}, fmt.Errorf("invalid split spec %q: empty app entry", spec)
		}
		apps = append(apps, app)
	}
	return Settings{Mode: mode, Apps: normalizeApps(apps)}, nil
}
