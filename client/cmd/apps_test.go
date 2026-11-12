package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeAppArg(t *testing.T) {
	assert.Equal(t, "opera.exe", normalizeAppArg(`C:\Tools\Opera.EXE`))
	assert.Equal(t, "opera.exe", normalizeAppArg(`/usr/bin/opera.exe`))
	assert.Equal(t, "telegram.exe", normalizeAppArg("  telegram.exe  "))
	assert.Equal(t, "vlc.exe", normalizeAppArg("vlc.exe"))
}

func TestMergeApps(t *testing.T) {
	// Add normalizes to lower-cased base names and deduplicates within the
	// arguments and against the stored list.
	merged := mergeApps(
		[]string{"opera.exe"},
		[]string{`C:\Tools\Opera.EXE`, "telegram.exe", "opera.exe", "  VLC.EXE  "},
	)
	assert.Equal(t, []string{"opera.exe", "telegram.exe", "vlc.exe"}, merged)

	assert.Empty(t, mergeApps(nil, nil))
}

func TestDropApps(t *testing.T) {
	existing := []string{"opera.exe", "telegram.exe", "vlc.exe"}

	assert.Equal(t, []string{"opera.exe", "vlc.exe"}, dropApps(existing, []string{"telegram.exe"}))

	// Unknown apps are a no-op, and removal matches the normalized form only.
	assert.Equal(t, existing, dropApps(existing, []string{"missing.exe"}))
	assert.Equal(t, existing, dropApps(existing, nil))
}
