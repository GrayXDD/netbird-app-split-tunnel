package split

import "github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"

// Classifier attributes a connection to its owning executable.
type Classifier interface {
	// Owner returns the base name of the executable owning the connection
	// (lower case, e.g. "opera.exe"), and whether attribution succeeded.
	// On failure it returns ok=false; the engine then fails closed to
	// VerdictTunnel.
	Owner(key conntrack.ConnKey, proto Protocol) (exeBase string, ok bool)
}
