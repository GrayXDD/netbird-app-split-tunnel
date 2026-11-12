package split

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadStoreMissingFileYieldsOff(t *testing.T) {
	dir := t.TempDir()

	settings, err := LoadStore(dir)
	require.NoError(t, err)
	require.Equal(t, Settings{Mode: ModeOff}, settings)

	// The config dir itself may not exist yet either.
	settings, err = LoadStore(filepath.Join(dir, "missing"))
	require.NoError(t, err)
	require.Equal(t, Settings{Mode: ModeOff}, settings)
}

func TestStoreRoundtrip(t *testing.T) {
	dir := t.TempDir()
	in := Settings{Mode: ModeInclude, Apps: []string{"opera.exe", "telegram.exe"}}

	require.NoError(t, SaveStore(dir, in))

	out, err := LoadStore(dir)
	require.NoError(t, err)
	require.Equal(t, in, out)
}

func TestSaveStoreNormalizesOnLoad(t *testing.T) {
	dir := t.TempDir()
	in := Settings{Mode: ModeExclude, Apps: []string{"Opera.EXE", "opera.exe", " chat.exe"}}

	require.NoError(t, SaveStore(dir, in))

	out, err := LoadStore(dir)
	require.NoError(t, err)
	require.Equal(t, Settings{Mode: ModeExclude, Apps: []string{"chat.exe", "opera.exe"}}, out)
}

func TestSaveStoreLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, SaveStore(dir, Settings{Mode: ModeInclude, Apps: []string{"a.exe"}}))
	require.NoError(t, SaveStore(dir, Settings{Mode: ModeOff}))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "only split.json must remain")
	require.Equal(t, "split.json", entries[0].Name())
}

func TestLoadStoreInvalid(t *testing.T) {
	dir := t.TempDir()

	broken := filepath.Join(dir, storeFileName)
	require.NoError(t, os.WriteFile(broken, []byte("{not json"), 0o600))
	_, err := LoadStore(dir)
	require.Error(t, err)

	require.NoError(t, os.WriteFile(broken, []byte(`{"mode":"bogus","apps":[]}`), 0o600))
	_, err = LoadStore(dir)
	require.Error(t, err)
}
