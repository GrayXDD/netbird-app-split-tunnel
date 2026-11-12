//go:build !windows

package uspfilter

import (
	"net"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/bypass"
)

// newBypassDialer returns a plain dialer. Process attribution is only
// implemented on Windows, so elsewhere the bypass stack is never created and
// this dialer exists for completeness.
func newBypassDialer() bypass.DialContextFunc {
	return (&net.Dialer{Timeout: bypassDialTimeout}).DialContext
}
