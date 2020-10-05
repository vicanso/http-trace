package httptrace

import (
	"crypto/tls"
	"net"
	nht "net/http/httptrace"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestConvertTLSVersion(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("tls1.0", convertTLSVersion(tls.VersionTLS10))
	assert.Equal("1", convertTLSVersion(1))
}

func TestConvertCipherSuite(t *testing.T) {
	assert := assert.New(t)
	assert.Equal("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", convertCipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA))
	assert.Equal("1", convertCipherSuite(1))
}

func TestTrace(t *testing.T) {
	assert := assert.New(t)
	trace, ht := NewClientTrace()

	trace.GetConn("1.1.1.1:80")
	time.Sleep(time.Millisecond)

	trace.DNSStart(nht.DNSStartInfo{
		Host: "aslant.site",
	})
	time.Sleep(time.Millisecond)

	addrs := make([]net.IPAddr, 0)
	addrs = append(addrs, net.IPAddr{
		IP: net.IPv4(1, 1, 1, 1),
	})
	trace.DNSDone(nht.DNSDoneInfo{
		Addrs: addrs,
	})
	time.Sleep(time.Millisecond)

	trace.ConnectStart("tcp", "1.1.1.1")
	time.Sleep(time.Millisecond)

	trace.ConnectDone("", "", nil)
	time.Sleep(time.Millisecond)

	trace.TLSHandshakeStart()
	time.Sleep(time.Millisecond)

	trace.TLSHandshakeDone(tls.ConnectionState{}, nil)
	time.Sleep(time.Millisecond)

	trace.GotConn(nht.GotConnInfo{
		Reused:  true,
		WasIdle: true,
	})
	time.Sleep(time.Millisecond)

	trace.GotFirstResponseByte()
	time.Sleep(time.Millisecond)
	ht.Finish()

	stats := ht.Stats()
	assert.NotEqual(0, stats.GetConnection)
	assert.NotEqual(0, stats.DNSLookup)
	assert.NotEqual(0, stats.TCPConnection)
	assert.NotEqual(0, stats.TLSHandshake)
	assert.NotEqual(0, stats.ServerProcessing)
	assert.NotEqual(0, stats.ContentTransfer)
	assert.NotEqual(0, stats.Total)

	assert.NotEmpty(stats.String())
}
