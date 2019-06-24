// +build !go1.11

package httptrace

import "crypto/tls"

const (
	versionTLS13 = tls.VersionTLS13
)
