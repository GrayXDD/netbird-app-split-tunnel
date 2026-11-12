//go:build !android && !ios && !freebsd && !js

package services

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/client/proto"
)

// splitTunnelDaemon implements only the RPCs SplitTunnel calls. The embedded
// interface is nil, so any other call panics rather than passing quietly.
type splitTunnelDaemon struct {
	proto.DaemonServiceClient
	stored *proto.GetSplitTunnelResponse

	setRequests []*proto.SetSplitTunnelRequest
	downCalls   int
	upRequests  []*proto.UpRequest
}

func (d *splitTunnelDaemon) GetSplitTunnel(context.Context, *proto.GetSplitTunnelRequest, ...grpc.CallOption) (*proto.GetSplitTunnelResponse, error) {
	return d.stored, nil
}

func (d *splitTunnelDaemon) SetSplitTunnel(_ context.Context, in *proto.SetSplitTunnelRequest, _ ...grpc.CallOption) (*proto.SetSplitTunnelResponse, error) {
	d.setRequests = append(d.setRequests, in)
	return &proto.SetSplitTunnelResponse{}, nil
}

func (d *splitTunnelDaemon) Down(context.Context, *proto.DownRequest, ...grpc.CallOption) (*proto.DownResponse, error) {
	d.downCalls++
	return &proto.DownResponse{}, nil
}

func (d *splitTunnelDaemon) Up(_ context.Context, in *proto.UpRequest, _ ...grpc.CallOption) (*proto.UpResponse, error) {
	d.upRequests = append(d.upRequests, in)
	return &proto.UpResponse{}, nil
}

func TestSplitTunnelGetMapsDaemonResponse(t *testing.T) {
	daemon := &splitTunnelDaemon{stored: &proto.GetSplitTunnelResponse{
		Mode: "exclude",
		Apps: []string{"chrome.exe", "firefox.exe"},
	}}
	s := NewSplitTunnel(stubConn{client: daemon})

	got, err := s.Get(context.Background())
	require.NoError(t, err)
	assert.Equal(t, &SplitTunnelSettings{
		Mode: "exclude",
		Apps: []string{"chrome.exe", "firefox.exe"},
	}, got)
}

func TestSplitTunnelSetSendsSettings(t *testing.T) {
	daemon := &splitTunnelDaemon{}
	s := NewSplitTunnel(stubConn{client: daemon})

	err := s.Set(context.Background(), SplitTunnelSettings{Mode: "include", Apps: []string{"Spotify.EXE"}})
	require.NoError(t, err)
	require.Len(t, daemon.setRequests, 1)
	assert.Equal(t, "include", daemon.setRequests[0].GetMode())
	// The daemon normalizes (lowercase base names, dedup); the UI must not.
	assert.Equal(t, []string{"Spotify.EXE"}, daemon.setRequests[0].GetApps())
}

func TestSplitTunnelSetRejectsInvalidMode(t *testing.T) {
	daemon := &splitTunnelDaemon{}
	s := NewSplitTunnel(stubConn{client: daemon})

	for _, mode := range []string{"", "Include", "whitelist", "off "} {
		assert.Error(t, s.Set(context.Background(), SplitTunnelSettings{Mode: mode}), "mode %q must be rejected locally", mode)
	}
	assert.Empty(t, daemon.setRequests, "an invalid mode must not reach the daemon")
}

func TestSplitTunnelApplyRestartsConnection(t *testing.T) {
	daemon := &splitTunnelDaemon{}
	s := NewSplitTunnel(stubConn{client: daemon})

	require.NoError(t, s.Apply(context.Background()))
	assert.Equal(t, 1, daemon.downCalls)
	require.Len(t, daemon.upRequests, 1)
	// Synchronous Up, so Apply reports whether the reconnect actually landed.
	assert.False(t, daemon.upRequests[0].GetAsync())
}

func TestSplitTunnelRunningApps(t *testing.T) {
	s := NewSplitTunnel(stubConn{client: &splitTunnelDaemon{}})

	apps, err := s.RunningApps(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, apps, "a live system has running processes")

	exes := make(map[string]struct{}, len(apps))
	for i, app := range apps {
		base := filepath.Base(app.Path)
		assert.Equal(t, strings.ToLower(base), app.Exe, "Exe must be the lowercase base name of Path")
		assert.Equal(t, strings.TrimSuffix(base, filepath.Ext(base)), app.Name, "Name must be the base name without extension")
		if i > 0 {
			assert.LessOrEqual(t, apps[i-1].Name, app.Name, "apps must be sorted by Name ascending")
		}

		_, dup := exes[app.Exe]
		assert.False(t, dup, "Exe %q must appear once", app.Exe)
		exes[app.Exe] = struct{}{}
	}
}
