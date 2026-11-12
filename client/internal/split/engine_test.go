package split

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
)

// fakeClassifier returns a fixed attribution and counts calls.
type fakeClassifier struct {
	exe   string
	ok    bool
	calls int
}

func (f *fakeClassifier) Owner(conntrack.ConnKey, Protocol) (string, bool) {
	f.calls++
	return f.exe, f.ok
}

func testKey(sport, dport uint16) conntrack.ConnKey {
	return conntrack.ConnKey{
		SrcIP:   netip.MustParseAddr("100.64.0.1"),
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		SrcPort: sport,
		DstPort: dport,
	}
}

func TestDecideIncludeHitAndMiss(t *testing.T) {
	hit := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, hit)

	verdict, owner := e.Decide(testKey(1000, 443), ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict)
	require.Equal(t, "opera.exe", owner)

	miss := &fakeClassifier{exe: "chrome.exe", ok: true}
	e = NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, miss)

	verdict, owner = e.Decide(testKey(1001, 443), ProtoTCP)
	require.Equal(t, VerdictBypass, verdict)
	require.Equal(t, "chrome.exe", owner)
}

func TestDecideExcludeHitAndMiss(t *testing.T) {
	hit := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeExclude, Apps: []string{"opera.exe"}}, hit)

	verdict, owner := e.Decide(testKey(1002, 443), ProtoTCP)
	require.Equal(t, VerdictBypass, verdict)
	require.Equal(t, "opera.exe", owner)

	miss := &fakeClassifier{exe: "chrome.exe", ok: true}
	e = NewEngine(Settings{Mode: ModeExclude, Apps: []string{"opera.exe"}}, miss)

	verdict, _ = e.Decide(testKey(1003, 443), ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict)
}

func TestDecideOffShortCircuits(t *testing.T) {
	c := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeOff, Apps: []string{"opera.exe"}}, c)

	verdict, owner := e.Decide(testKey(1004, 443), ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict)
	require.Empty(t, owner)
	require.Zero(t, c.calls, "mode off must not consult the classifier")
}

func TestDecideClassifierMissFailsClosed(t *testing.T) {
	c := &fakeClassifier{exe: "", ok: false}
	e := NewEngine(Settings{Mode: ModeExclude, Apps: []string{"opera.exe"}}, c)

	verdict, owner := e.Decide(testKey(1005, 443), ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict)
	require.Empty(t, owner)
}

func TestDecideCachesVerdict(t *testing.T) {
	c := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, c)

	key := testKey(1006, 443)
	_, _ = e.Decide(key, ProtoTCP)
	_, _ = e.Decide(key, ProtoTCP)
	_, _ = e.Decide(key, ProtoUDP)
	require.Equal(t, 1, c.calls, "verdicts must be cached per flow key")

	other := testKey(1007, 443)
	_, _ = e.Decide(other, ProtoTCP)
	require.Equal(t, 2, c.calls)
}

func TestDecideCacheExpiry(t *testing.T) {
	c := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, c)
	// The closure captures the test variable, so advancing at moves the clock.
	at := time.Now()
	e.now = func() time.Time { return at }
	e.lastSweep = at

	key := testKey(1008, 443)
	_, _ = e.Decide(key, ProtoTCP)
	_, _ = e.Decide(key, ProtoTCP)
	require.Equal(t, 1, c.calls)

	at = at.Add(verdictTTL + time.Second)
	_, _ = e.Decide(key, ProtoTCP)
	require.Equal(t, 2, c.calls, "verdict must be re-classified after TTL")
}

func TestDecideSweepsExpiredEntries(t *testing.T) {
	c := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, c)
	at := time.Now()
	e.now = func() time.Time { return at }
	e.lastSweep = at

	expiredKey := testKey(1009, 443)
	_, _ = e.Decide(expiredKey, ProtoTCP)
	at = at.Add(2 * verdictTTL)
	freshKey := testKey(1010, 443)
	_, _ = e.Decide(freshKey, ProtoTCP)

	require.Len(t, e.cache, 1, "expired entries must be swept, fresh ones kept")
	_, ok := e.cache[expiredKey]
	require.False(t, ok, "expired entry must be gone")
	_, ok = e.cache[freshKey]
	require.True(t, ok, "fresh entry must be kept")
}

func TestUpdateResetsCacheAndSettings(t *testing.T) {
	c := &fakeClassifier{exe: "opera.exe", ok: true}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, c)

	key := testKey(1011, 443)
	verdict, _ := e.Decide(key, ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict)

	e.Update(Settings{Mode: ModeExclude, Apps: []string{"opera.exe"}})
	verdict, _ = e.Decide(key, ProtoTCP)
	require.Equal(t, VerdictBypass, verdict)
	require.Equal(t, 2, c.calls, "Update must drop cached verdicts")

	e.Update(Settings{Mode: ModeOff})
	verdict, owner := e.Decide(key, ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict)
	require.Empty(t, owner)
	require.Equal(t, 2, c.calls)
}

func TestUpdateNormalizesApps(t *testing.T) {
	e := NewEngine(Settings{Mode: ModeOff}, &fakeClassifier{})
	e.Update(Settings{Mode: ModeInclude, Apps: []string{"Opera.EXE", " opera.exe ", "CHAT.exe", ""}})
	require.Equal(t, []string{"chat.exe", "opera.exe"}, e.settings.Apps)
}

func TestNewEngineCopiesApps(t *testing.T) {
	apps := []string{"opera.exe"}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: apps}, &fakeClassifier{exe: "opera.exe", ok: true})
	apps[0] = "mutated.exe"

	verdict, _ := e.Decide(testKey(1012, 443), ProtoTCP)
	require.Equal(t, VerdictTunnel, verdict, "engine must not share backing storage with caller's slice")
}

// blockingClassifier blocks classification of one key until released and lets
// every other lookup through, so tests can pin a single classification.
type blockingClassifier struct {
	blockKey conntrack.ConnKey
	release  chan struct{}
	started  chan struct{}
}

func (b *blockingClassifier) Owner(key conntrack.ConnKey, _ Protocol) (string, bool) {
	if key == b.blockKey {
		b.started <- struct{}{}
		<-b.release
		return "blocked.exe", true
	}
	return "other.exe", true
}

// TestDecideDoesNotBlockOtherFlows verifies that a slow classification (the
// Windows classifier may re-read socket and process tables) does not hold the
// engine lock: verdicts for other flows must still be served.
func TestDecideDoesNotBlockOtherFlows(t *testing.T) {
	blockKey := testKey(2000, 443)
	c := &blockingClassifier{
		blockKey: blockKey,
		release:  make(chan struct{}),
		started:  make(chan struct{}),
	}
	e := NewEngine(Settings{Mode: ModeInclude, Apps: []string{"opera.exe"}}, c)

	go e.Decide(blockKey, ProtoTCP)
	<-c.started

	done := make(chan struct{})
	go func() {
		defer close(done)
		verdict, owner := e.Decide(testKey(2001, 443), ProtoTCP)
		require.Equal(t, VerdictBypass, verdict)
		require.Equal(t, "other.exe", owner)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Decide for another flow blocked behind an in-flight classification")
	}

	close(c.release)
}
