package split

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// storeFileName is the settings file inside the config dir.
const storeFileName = "split.json"

// storeFile is the on-disk shape of the split tunnel settings.
type storeFile struct {
	Mode string   `json:"mode"`
	Apps []string `json:"apps"`
}

// LoadStore reads split.json from configDir. A missing file (or dir) means
// the feature was never configured and yields the default: ModeOff with no
// apps.
func LoadStore(configDir string) (Settings, error) {
	data, err := os.ReadFile(filepath.Join(configDir, storeFileName))
	if errors.Is(err, fs.ErrNotExist) {
		return Settings{Mode: ModeOff}, nil
	}
	if err != nil {
		return Settings{}, fmt.Errorf("read split store: %w", err)
	}

	var f storeFile
	if err := json.Unmarshal(data, &f); err != nil {
		return Settings{}, fmt.Errorf("parse split store: %w", err)
	}
	mode, err := ParseMode(f.Mode)
	if err != nil {
		return Settings{}, fmt.Errorf("parse split store: %w", err)
	}
	return Settings{Mode: mode, Apps: normalizeApps(f.Apps)}, nil
}

// SaveStore atomically writes the settings to split.json in configDir: the
// data is written to a temp file in the same directory and then renamed over
// the target, so readers only ever see a complete file.
func SaveStore(configDir string, s Settings) error {
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(storeFile{Mode: s.Mode.String(), Apps: s.Apps}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal split store: %w", err)
	}
	data = append(data, '\n')

	target := filepath.Join(configDir, storeFileName)
	tmp, err := os.CreateTemp(configDir, "."+storeFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, target); err != nil {
		return fmt.Errorf("replace split store: %w", err)
	}
	return nil
}
