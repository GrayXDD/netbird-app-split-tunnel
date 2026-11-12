//go:build !windows

package split

import "github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"

// noopClassifier never attributes a connection to a process: process
// attribution is only implemented on Windows. Every lookup misses, so the
// engine keeps all traffic in the tunnel (fail-closed) on other platforms.
type noopClassifier struct{}

// NewProcessClassifier returns a Classifier that never attributes a
// connection to a process.
func NewProcessClassifier() Classifier {
	return noopClassifier{}
}

func (noopClassifier) Owner(conntrack.ConnKey, Protocol) (string, bool) {
	return "", false
}
