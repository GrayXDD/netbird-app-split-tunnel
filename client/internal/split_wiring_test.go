package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/split"
	"github.com/netbirdio/netbird/route"
)

func TestResolveSplitSettingsEnvOverridesStore(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, split.SaveStore(dir, split.Settings{Mode: split.ModeExclude, Apps: []string{"chrome.exe"}}))

	t.Setenv(SplitTunnelEnv, "include:opera.exe,telegram.exe")
	settings, err := resolveSplitSettings(dir)
	require.NoError(t, err)
	require.Equal(t, split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe", "telegram.exe"}}, settings)
}

func TestResolveSplitSettingsFallsBackToStore(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, split.SaveStore(dir, split.Settings{Mode: split.ModeExclude, Apps: []string{"Chrome.exe", "chrome.exe"}}))

	t.Setenv(SplitTunnelEnv, "")
	settings, err := resolveSplitSettings(dir)
	require.NoError(t, err)
	require.Equal(t, split.Settings{Mode: split.ModeExclude, Apps: []string{"chrome.exe"}}, settings)
}

func TestResolveSplitSettingsMissingEverythingIsOff(t *testing.T) {
	dir := t.TempDir()

	t.Setenv(SplitTunnelEnv, "")
	settings, err := resolveSplitSettings(dir)
	require.NoError(t, err)
	require.Equal(t, split.Settings{Mode: split.ModeOff}, settings)
}

func TestResolveSplitSettingsInvalidEnvDegradesToOff(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, split.SaveStore(dir, split.Settings{Mode: split.ModeInclude, Apps: []string{"opera.exe"}}))

	t.Setenv(SplitTunnelEnv, "not-a-mode:opera.exe")
	settings, err := resolveSplitSettings(dir)
	require.NoError(t, err)
	require.Equal(t, split.Settings{Mode: split.ModeOff}, settings)
}

func TestSplitTunnelRoutePrefixes(t *testing.T) {
	corp := netip.MustParsePrefix("10.10.0.0/24")
	corpV6 := netip.MustParsePrefix("fd00:1234::/48")
	catchAll4 := netip.MustParsePrefix("0.0.0.0/0")
	catchAll6 := netip.MustParsePrefix("::/0")

	ha := route.HAMap{
		"ha-corp": {
			&route.Route{Network: corp},
			&route.Route{Network: catchAll4},
		},
		"ha-corp-v6": {
			&route.Route{Network: corpV6},
			&route.Route{Network: catchAll6},
		},
	}

	got := splitTunnelRoutePrefixes(ha)
	require.ElementsMatch(t, []netip.Prefix{corp, corpV6}, got,
		"specific route networks must be kept, catch-alls dropped")
}
