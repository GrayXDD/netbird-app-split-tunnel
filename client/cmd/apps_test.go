package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/split"
)

// runAppsCmd executes an apps subcommand and returns its output. The config
// dir is pointed at dir via the overridable appsConfigDir variable.
func runAppsCmd(t *testing.T, dir string, args ...string) (string, error) {
	t.Helper()

	prev := appsConfigDir
	appsConfigDir = dir
	t.Cleanup(func() { appsConfigDir = prev })

	buf := &bytes.Buffer{}
	appsCmd.SetOut(buf)
	appsCmd.SetErr(buf)
	appsCmd.SetArgs(args)
	err := appsCmd.Execute()
	return buf.String(), err
}

// The apps tests share the global appsConfigDir override, so they must not
// run in parallel with each other.
func TestAppsRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// No store file yet: the default is mode off with an empty list, and no
	// file is created by a read.
	out, err := runAppsCmd(t, dir, "list")
	require.NoError(t, err)
	assert.Contains(t, out, "Mode: off")
	assert.Contains(t, out, "Applications: none")
	_, err = split.LoadStore(dir)
	require.NoError(t, err)

	// Add normalizes to lower-cased base names, deduplicates within the
	// arguments and against the stored list.
	operaPath := filepath.Join("C:", "Tools", "Opera.EXE")
	_, err = runAppsCmd(t, dir, "add", operaPath, "telegram.exe", "opera.exe", "  VLC.EXE  ")
	require.NoError(t, err)

	s, err := split.LoadStore(dir)
	require.NoError(t, err)
	assert.Equal(t, split.ModeOff, s.Mode, "add must not change the mode")
	assert.Equal(t, []string{"opera.exe", "telegram.exe", "vlc.exe"}, s.Apps)

	out, err = runAppsCmd(t, dir, "list")
	require.NoError(t, err)
	assert.Contains(t, out, "opera.exe, telegram.exe, vlc.exe")

	// Mode switch keeps the app list.
	out, err = runAppsCmd(t, dir, "mode", "include")
	require.NoError(t, err)
	assert.Contains(t, out, "Mode: include")
	assert.Contains(t, out, applyHint)

	s, err = split.LoadStore(dir)
	require.NoError(t, err)
	assert.Equal(t, split.ModeInclude, s.Mode)
	assert.Equal(t, []string{"opera.exe", "telegram.exe", "vlc.exe"}, s.Apps)

	// Remove matches case-insensitively; every mutation prints the apply hint.
	out, err = runAppsCmd(t, dir, "remove", "TELEGRAM.EXE")
	require.NoError(t, err)
	assert.Contains(t, out, applyHint)

	s, err = split.LoadStore(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"opera.exe", "vlc.exe"}, s.Apps)

	// Removing an app that is not listed is a no-op that keeps the store.
	_, err = runAppsCmd(t, dir, "remove", "missing.exe")
	require.NoError(t, err)

	s, err = split.LoadStore(dir)
	require.NoError(t, err)
	assert.Equal(t, []string{"opera.exe", "vlc.exe"}, s.Apps)
}

func TestAppsModeRejectsUnknownMode(t *testing.T) {
	dir := t.TempDir()
	_, err := runAppsCmd(t, dir, "add", "opera.exe")
	require.NoError(t, err)

	_, err = runAppsCmd(t, dir, "mode", "bogus")
	require.ErrorContains(t, err, "unknown split mode")

	// The failed switch must not touch the stored settings.
	s, err := split.LoadStore(dir)
	require.NoError(t, err)
	assert.Equal(t, split.ModeOff, s.Mode)
	assert.Equal(t, []string{"opera.exe"}, s.Apps)
}

func TestAppsAddRequiresArgument(t *testing.T) {
	_, err := runAppsCmd(t, t.TempDir(), "add")
	require.Error(t, err)
	assert.ErrorContains(t, err, "requires at least 1 arg(s)")
}
