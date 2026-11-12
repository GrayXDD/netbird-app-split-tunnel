//go:build windows

package uspfilter

import (
	"github.com/netbirdio/netbird/client/firewall/uspfilter/bypass"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// newBypassDialer returns the dialer for bypassed connections. The nbnet
// dialer's Control hook binds every socket to the physical interface chosen
// for the destination (applyUnicastIFToSocket), so bypassed traffic does not
// loop back into the tunnel.
func newBypassDialer() bypass.DialContextFunc {
	d := nbnet.NewDialer()
	d.Timeout = bypassDialTimeout
	return d.Dialer.DialContext
}
