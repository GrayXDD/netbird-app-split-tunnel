package cmd

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/grpc/status"

	"github.com/netbirdio/netbird/client/internal/split"
	"github.com/netbirdio/netbird/client/proto"
)

// applyHint tells the user when an apps change takes effect: a connected
// daemon applies it to the live firewall immediately, a disconnected one picks
// it up on the next connect.
const applyHint = "If the service is not connected, the change applies on the next connection."

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

// appsClient dials the daemon and returns its service client with a closer.
// A dial failure is reported the same way every other daemon command does,
// including the "start the service" hint.
func appsClient(cmd *cobra.Command) (proto.DaemonServiceClient, func(), error) {
	conn, err := getClient(cmd)
	if err != nil {
		return nil, nil, err
	}
	return proto.NewDaemonServiceClient(conn), func() { _ = conn.Close() }, nil
}

// fetchAppsSettings loads the current settings from the daemon.
func fetchAppsSettings(cmd *cobra.Command, client proto.DaemonServiceClient) (split.Settings, error) {
	resp, err := client.GetSplitTunnel(cmd.Context(), &proto.GetSplitTunnelRequest{})
	if err != nil {
		return split.Settings{}, fmt.Errorf("failed to get split tunnel settings: %v", status.Convert(err).Message())
	}

	mode, err := split.ParseMode(resp.Mode)
	if err != nil {
		return split.Settings{}, fmt.Errorf("daemon returned an unknown split mode %q", resp.Mode)
	}
	return split.Settings{Mode: mode, Apps: resp.Apps}, nil
}

// saveAppsSettings replaces the settings on the daemon with the full list and
// prints the resulting state plus the apply hint.
func saveAppsSettings(cmd *cobra.Command, client proto.DaemonServiceClient, s split.Settings) error {
	req := &proto.SetSplitTunnelRequest{
		Mode: s.Mode.String(),
		Apps: s.Apps,
	}
	if _, err := client.SetSplitTunnel(cmd.Context(), req); err != nil {
		return fmt.Errorf("failed to set split tunnel settings: %v", status.Convert(err).Message())
	}

	printAppsSettings(cmd, s)
	cmd.Println(applyHint)
	return nil
}

// normalizeAppArg turns a user-supplied path into the stored form: the base
// name, trimmed and lower-cased (e.g. `C:\Tools\Opera.EXE` -> `opera.exe`).
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

func appsList(cmd *cobra.Command, _ []string) error {
	client, closeConn, err := appsClient(cmd)
	if err != nil {
		return err
	}
	defer closeConn()

	s, err := fetchAppsSettings(cmd, client)
	if err != nil {
		return err
	}
	printAppsSettings(cmd, s)
	return nil
}

func appsAdd(cmd *cobra.Command, args []string) error {
	client, closeConn, err := appsClient(cmd)
	if err != nil {
		return err
	}
	defer closeConn()

	s, err := fetchAppsSettings(cmd, client)
	if err != nil {
		return err
	}
	s.Apps = mergeApps(s.Apps, args)
	return saveAppsSettings(cmd, client, s)
}

func appsRemove(cmd *cobra.Command, args []string) error {
	client, closeConn, err := appsClient(cmd)
	if err != nil {
		return err
	}
	defer closeConn()

	s, err := fetchAppsSettings(cmd, client)
	if err != nil {
		return err
	}
	removed := make([]string, 0, len(args))
	for _, arg := range args {
		removed = append(removed, normalizeAppArg(arg))
	}
	s.Apps = dropApps(s.Apps, removed)
	return saveAppsSettings(cmd, client, s)
}

func appsMode(cmd *cobra.Command, args []string) error {
	mode, err := split.ParseMode(args[0])
	if err != nil {
		return err
	}

	client, closeConn, err := appsClient(cmd)
	if err != nil {
		return err
	}
	defer closeConn()

	s, err := fetchAppsSettings(cmd, client)
	if err != nil {
		return err
	}
	s.Mode = mode
	return saveAppsSettings(cmd, client, s)
}
