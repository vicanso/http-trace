// +build go1.11

package httptrace

const (
	versionTLS13 = 0x0304
)

const (
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9
	TLS_AES_128_GCM_SHA256                        uint16 = 0x1301
	TLS_AES_256_GCM_SHA384                        uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256                  uint16 = 0x1303
)
