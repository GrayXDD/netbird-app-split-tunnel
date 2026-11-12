//go:build !android && !ios && !freebsd && !js

package services

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v4/process"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/proto"
	"github.com/wailsapp/wails/v3/pkg/application"
)

// SplitTunnelSettings is the daemon's per-app split tunnel configuration.
// Mode is off|include|exclude; Apps holds executable base names (lowercase).
type SplitTunnelSettings struct {
	Mode string   `json:"mode"`
	Apps []string `json:"apps"`
}

// RunningApp describes one distinct running executable, offered for picking
// into the split tunnel app list.
type RunningApp struct {
	// Exe is the lowercase base name of the executable — the form stored in
	// the app list.
	Exe string `json:"exe"`
	// Name is the base name without extension, for display.
	Name string `json:"name"`
	// Path is the full executable path.
	Path string `json:"path"`
}

// SplitTunnel is the Wails-bound facade over the daemon's split tunnel RPCs.
type SplitTunnel struct {
	conn DaemonConn
}

func NewSplitTunnel(conn DaemonConn) *SplitTunnel {
	return &SplitTunnel{conn: conn}
}

// Get returns the split tunnel settings stored by the daemon.
func (s *SplitTunnel) Get(ctx context.Context) (*SplitTunnelSettings, error) {
	cli, err := s.conn.Client()
	if err != nil {
		return nil, err
	}
	resp, err := cli.GetSplitTunnel(ctx, &proto.GetSplitTunnelRequest{})
	if err != nil {
		return nil, err
	}
	return &SplitTunnelSettings{
		Mode: resp.GetMode(),
		Apps: append([]string{}, resp.GetApps()...),
	}, nil
}

// Set stores new split tunnel settings. Mode is validated locally; the app
// list is passed through as-is for the daemon to normalize.
func (s *SplitTunnel) Set(ctx context.Context, settings SplitTunnelSettings) error {
	if !isValidSplitTunnelMode(settings.Mode) {
		return fmt.Errorf("invalid split tunnel mode %q: must be off, include or exclude", settings.Mode)
	}
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	_, err = cli.SetSplitTunnel(ctx, &proto.SetSplitTunnelRequest{
		Mode: settings.Mode,
		Apps: settings.Apps,
	})
	return err
}

// Apply restarts the connection so the daemon picks up changed split tunnel
// settings: Down, then a synchronous Up so the call returns only once the
// client is connected again (the daemon caps the wait at its own timeout).
func (s *SplitTunnel) Apply(ctx context.Context) error {
	cli, err := s.conn.Client()
	if err != nil {
		return err
	}
	log.Infof("restarting connection to apply split tunnel settings")
	if _, err := cli.Down(ctx, &proto.DownRequest{}); err != nil {
		return err
	}
	if _, err := cli.Up(ctx, &proto.UpRequest{Async: false}); err != nil {
		return err
	}
	log.Infof("connection restarted with new split tunnel settings")
	return nil
}

// RunningApps lists the distinct executables currently running, sorted by
// display name. Per-process errors are skipped; a context without its own
// deadline gets a 2s cap so a stuck enumeration cannot hang the UI.
func (s *SplitTunnel) RunningApps(ctx context.Context) ([]RunningApp, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
	}

	pids, err := process.PidsWithContext(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, len(pids))
	apps := make([]RunningApp, 0, len(pids))
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		p := &process.Process{Pid: pid}

		path, _ := p.ExeWithContext(ctx)
		if path == "" {
			continue
		}
		base := filepath.Base(path)
		exe := strings.ToLower(base)
		if _, dup := seen[exe]; dup {
			continue
		}
		seen[exe] = struct{}{}
		apps = append(apps, RunningApp{
			Exe:  exe,
			Name: strings.TrimSuffix(base, filepath.Ext(base)),
			Path: path,
		})
	}
	if len(apps) == 0 {
		return nil, fmt.Errorf("no running processes with an executable path found")
	}

	slices.SortFunc(apps, func(a, b RunningApp) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return apps, nil
}

// PickAppExe opens the native file dialog to pick an executable file. It
// returns the full path of the chosen file, or an empty string when the
// dialog is dismissed without a selection (no error). The dialog is modal
// and blocks until the user picks or cancels.
func (s *SplitTunnel) PickAppExe(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	app := application.Get()
	if app == nil || app.Dialog == nil {
		return "", fmt.Errorf("application is not running")
	}

	dialog := app.Dialog.OpenFile()
	dialog.SetTitle("Open executable file")
	dialog.AddFilter("Executable files (*.exe)", "*.exe")
	dialog.AddFilter("All files (*.*)", "*.*")

	path, err := dialog.PromptForSingleSelection()
	if err != nil {
		// Wails reports the OS cancellation as an error on Windows (the
		// sentinel lives in an internal package, so match by text) and as an
		// empty selection elsewhere.
		if isDialogCancelled(err) {
			return "", nil
		}
		return "", err
	}
	return path, nil
}

func isDialogCancelled(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "cancel")
}

func isValidSplitTunnelMode(mode string) bool {
	switch mode {
	case "off", "include", "exclude":
		return true
	}
	return false
}
