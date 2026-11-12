package split

import (
	"slices"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
)

// verdictTTL is how long a flow verdict is reused before the owning process
// is classified again.
const verdictTTL = time.Minute

// cacheEntry is a cached verdict for a single connection.
type cacheEntry struct {
	verdict Verdict
	owner   string
	expires time.Time
}

// Engine decides per connection whether its traffic is tunneled or bypassed,
// based on the owning application reported by a Classifier. Verdicts are
// cached per flow key with a TTL. It is safe for concurrent use.
type Engine struct {
	mu         sync.Mutex
	settings   Settings
	classifier Classifier
	cache      map[conntrack.ConnKey]cacheEntry
	now        func() time.Time
	lastSweep  time.Time
	// gen counts settings changes; it lets Decide skip caching a verdict
	// that was decided under settings replaced while it classified.
	gen uint64
}

// NewEngine returns an engine applying the given settings. The settings are
// normalized, and s.Apps is copied, so later mutations by the caller have no
// effect on the engine.
func NewEngine(s Settings, c Classifier) *Engine {
	now := time.Now()
	return &Engine{
		settings:   Settings{Mode: s.Mode, Apps: normalizeApps(s.Apps)},
		classifier: c,
		cache:      make(map[conntrack.ConnKey]cacheEntry),
		now:        time.Now,
		lastSweep:  now,
	}
}

// Update replaces the settings (normalized, copied) and drops all cached
// verdicts.
func (e *Engine) Update(s Settings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.settings = Settings{Mode: s.Mode, Apps: normalizeApps(s.Apps)}
	e.cache = make(map[conntrack.ConnKey]cacheEntry)
	e.gen++
}

// Decide returns the verdict for the connection identified by key, and the
// executable the connection was attributed to (empty when attribution
// failed). When the mode is off it short-circuits to VerdictTunnel without
// consulting the classifier or the cache. A classification miss yields
// VerdictTunnel (fail-closed).
//
// Classification runs without the engine lock: the Windows classifier may
// re-read socket and process tables for tens of milliseconds, and other flows
// must not queue behind it. The lock is held only for cache and settings
// access.
func (e *Engine) Decide(key conntrack.ConnKey, proto Protocol) (Verdict, string) {
	e.mu.Lock()

	if e.settings.Mode == ModeOff {
		e.mu.Unlock()
		return VerdictTunnel, ""
	}

	now := e.now()
	if entry, ok := e.cache[key]; ok {
		if now.Before(entry.expires) {
			e.mu.Unlock()
			return entry.verdict, entry.owner
		}
		delete(e.cache, key)
	}
	e.sweepExpired(now)
	// Snapshot the settings: Apps slices are replaced wholesale by
	// NewEngine/Update and never mutated in place, so the copy is safe to
	// read without the lock.
	settings := e.settings
	gen := e.gen
	e.mu.Unlock()

	owner, ok := e.classifier.Owner(key, proto)
	if !ok {
		owner = ""
	}

	verdict := VerdictTunnel
	if ok {
		listed := slices.Contains(settings.Apps, owner)
		switch settings.Mode {
		case ModeInclude:
			if !listed {
				verdict = VerdictBypass
			}
		case ModeExclude:
			if listed {
				verdict = VerdictBypass
			}
		}
	}

	e.mu.Lock()
	if e.gen == gen {
		e.cache[key] = cacheEntry{verdict: verdict, owner: owner, expires: now.Add(verdictTTL)}
	}
	e.mu.Unlock()
	return verdict, owner
}

// sweepExpired drops expired cache entries at most once per TTL period, so
// the lazily maintained map cannot grow without bound.
func (e *Engine) sweepExpired(now time.Time) {
	if now.Sub(e.lastSweep) < verdictTTL {
		return
	}
	for key, entry := range e.cache {
		if !now.Before(entry.expires) {
			delete(e.cache, key)
		}
	}
	e.lastSweep = now
}
