package cmd

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/internal/split"
)

// applyHint tells the user when an apps change takes effect: the daemon reads
// split.json on connect only, there is no hot reload.
const applyHint = "Применится при следующем подключении (netbird down && netbird up или перезапуск сервиса)"

// appsConfigDir overrides the config directory the apps commands read and
// write. Empty means the default engine state dir; tests set it to a temp dir.
var appsConfigDir string

var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "Manage the list of tunneled applications",
	Long:  "Commands to manage the per-app split tunnel list: add or remove applications, switch the mode, and show the current settings.",
}

var appsListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List split tunnel mode and applications",
	Example: "  netbird apps list",
	RunE:    appsList,
}

var appsAddCmd = &cobra.Command{
	Use:     "add exe...",
	Short:   "Add applications to the split tunnel list",
	Example: "  netbird apps add opera.exe telegram.exe",
	Args:    cobra.MinimumNArgs(1),
	RunE:    appsAdd,
}

var appsRemoveCmd = &cobra.Command{
	Use:     "remove exe...",
	Short:   "Remove applications from the split tunnel list",
	Example: "  netbird apps remove opera.exe",
	Args:    cobra.MinimumNArgs(1),
	RunE:    appsRemove,
}

var appsModeCmd = &cobra.Command{
	Use:     "mode off|include|exclude",
	Short:   "Set the split tunnel mode",
	Example: "  netbird apps mode include",
	Args:    cobra.ExactArgs(1),
	RunE:    appsMode,
}

// appsDir returns the directory holding split.json: the same state dir the
// split tunnel engine uses (NB_STATE_DIR if set, otherwise the profilemanager
// default). root.go's legacy config resolution is intentionally not reused,
// so the behavior of the other commands stays untouched.
func appsDir() string {
	if appsConfigDir != "" {
		return appsConfigDir
	}
	return profilemanager.DefaultConfigPathDir
}

// normalizeAppArg turns a user-supplied path into the stored form: the base
// name, trimmed and lower-cased (e.g. `C:\\Tools\\Opera.EXE` -> `opera.exe`).
func normalizeAppArg(app string) string {
	return strings.ToLower(filepath.Base(strings.TrimSpace(app)))
}

// mergeApps merges added into existing: normalized base names, deduplicated
// and sorted.
func mergeApps(existing, added []string) []string {
	apps := make([]string, 0, len(existing)+len(added))
	apps = append(apps, existing...)
	for _, app := range added {
		app = normalizeAppArg(app)
		if app == "" || slices.Contains(apps, app) {
			continue
		}
		apps = append(apps, app)
	}
	slices.Sort(apps)
	return apps
}

// dropApps removes removed from existing, matching normalized base names.
func dropApps(existing, removed []string) []string {
	apps := make([]string, 0, len(existing))
	for _, app := range existing {
		if !slices.Contains(removed, app) {
			apps = append(apps, app)
		}
	}
	return apps
}

// printAppsSettings prints the resulting mode and application list.
func printAppsSettings(cmd *cobra.Command, s split.Settings) {
	cmd.Printf("Mode: %s\n", s.Mode)
	if len(s.Apps) == 0 {
		cmd.Println("Applications: none")
		return
	}
	cmd.Printf("Applications: %s\n", strings.Join(s.Apps, ", "))
}

// saveAppsStore persists the settings and prints the resulting state plus the
// apply hint, as every mutation takes effect on the next connection only.
func saveAppsStore(cmd *cobra.Command, s split.Settings) error {
	if err := split.SaveStore(appsDir(), s); err != nil {
		return fmt.Errorf("save split tunnel settings: %w", err)
	}
	printAppsSettings(cmd, s)
	cmd.Println(applyHint)
	return nil
}

func appsList(cmd *cobra.Command, _ []string) error {
	s, err := split.LoadStore(appsDir())
	if err != nil {
		return fmt.Errorf("load split tunnel settings: %w", err)
	}
	printAppsSettings(cmd, s)
	return nil
}

func appsAdd(cmd *cobra.Command, args []string) error {
	s, err := split.LoadStore(appsDir())
	if err != nil {
		return fmt.Errorf("load split tunnel settings: %w", err)
	}
	s.Apps = mergeApps(s.Apps, args)
	return saveAppsStore(cmd, s)
}

func appsRemove(cmd *cobra.Command, args []string) error {
	s, err := split.LoadStore(appsDir())
	if err != nil {
		return fmt.Errorf("load split tunnel settings: %w", err)
	}
	removed := make([]string, 0, len(args))
	for _, arg := range args {
		removed = append(removed, normalizeAppArg(arg))
	}
	s.Apps = dropApps(s.Apps, removed)
	return saveAppsStore(cmd, s)
}

func appsMode(cmd *cobra.Command, args []string) error {
	mode, err := split.ParseMode(args[0])
	if err != nil {
		return err
	}
	s, err := split.LoadStore(appsDir())
	if err != nil {
		return fmt.Errorf("load split tunnel settings: %w", err)
	}
	s.Mode = mode
	return saveAppsStore(cmd, s)
}
