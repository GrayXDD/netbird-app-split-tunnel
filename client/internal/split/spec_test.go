package split

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseMode(t *testing.T) {
	for name, want := range map[string]Mode{
		"off":     ModeOff,
		"include": ModeInclude,
		"exclude": ModeExclude,
		" OFF ":   ModeOff,
		"Include": ModeInclude,
	} {
		got, err := ParseMode(name)
		require.NoError(t, err, name)
		require.Equal(t, want, got, name)
	}

	got, err := ParseMode("bogus")
	require.Error(t, err)
	require.Equal(t, ModeOff, got)
}

func TestModeString(t *testing.T) {
	require.Equal(t, "off", ModeOff.String())
	require.Equal(t, "include", ModeInclude.String())
	require.Equal(t, "exclude", ModeExclude.String())
	require.Equal(t, "off", Mode(42).String())
}

func TestParseSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		want    Settings
		wantErr bool
	}{
		{
			name: "empty spec means off",
			spec: "",
			want: Settings{Mode: ModeOff},
		},
		{
			name: "whitespace only means off",
			spec: "   ",
			want: Settings{Mode: ModeOff},
		},
		{
			name: "bare off means off",
			spec: "off",
			want: Settings{Mode: ModeOff},
		},
		{
			name: "include two apps",
			spec: "include:opera.exe,telegram.exe",
			want: Settings{Mode: ModeInclude, Apps: []string{"opera.exe", "telegram.exe"}},
		},
		{
			name: "apps are normalized",
			spec: "EXCLUDE: Opera.EXE , x.exe ,X.exe",
			want: Settings{Mode: ModeExclude, Apps: []string{"opera.exe", "x.exe"}},
		},
		{
			name:    "unknown mode",
			spec:    "bogus:a.exe",
			wantErr: true,
		},
		{
			name:    "non-off mode without apps",
			spec:    "include",
			wantErr: true,
		},
		{
			name:    "empty apps list",
			spec:    "include:",
			wantErr: true,
		},
		{
			name:    "empty app entry",
			spec:    "include:opera.exe,,telegram.exe",
			wantErr: true,
		},
		{
			name:    "comma only",
			spec:    "include:,",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseSpec(tt.spec)
			if tt.wantErr {
				require.Error(t, err, "spec %q", tt.spec)
				return
			}
			require.NoError(t, err, "spec %q", tt.spec)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNormalizeApps(t *testing.T) {
	require.Equal(t, []string{"a.exe", "b.exe", "c.exe"},
		normalizeApps([]string{"C.EXE", " b.exe ", "a.exe", "", "c.exe", "B.exe"}))
	require.Empty(t, normalizeApps([]string{"", "   "}))
	require.Empty(t, normalizeApps(nil))
}
