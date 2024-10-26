// Copyright 2019 tree xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httptrace

import (
	"crypto/tls"
	"fmt"
	"net/http/httptrace"
	"strconv"
	"strings"
	"time"
)

type (
	// HTTPTimelineStats http timeline stats
	HTTPTimelineStats struct {
		// dns lookup time
		DNSLookup time.Duration `json:"dnsLookup,omitempty"`
		// get connection time
		GetConnection time.Duration `json:"getConnection,omitempty"`
		// tcp connection time
		TCPConnection time.Duration `json:"tcpConnection,omitempty"`
		// tls handshake time
		TLSHandshake time.Duration `json:"tlsHandshake,omitempty"`
		// request body send time
		RequestSend time.Duration `json:"requestSend"`
		// server processing time
		ServerProcessing time.Duration `json:"serverProcessing,omitempty"`
		// content transfer time
		ContentTransfer time.Duration `json:"contentTransfer,omitempty"`
		// unmarshal time
		Unmarshal time.Duration `json:"unmarshal,omitempty"`
		// total time
		Total time.Duration `json:"total,omitempty"`
	}

	tlsCertificate struct {
		// dns names of tls certificate
		DNSNames []string `json:"dnsNames,omitempty"`
		// certificate is valid not before
		NotBefore time.Time `json:"notBefore,omitempty"`
		// certificate is valid not after
		NotAfter time.Time `json:"notAfter,omitempty"`
	}

	// HTTPTrace http trace
	HTTPTrace struct {
		// http request host
		Host string `json:"host,omitempty"`
		// addrs of host
		Addrs []string `json:"addrs,omitempty"`
		// network type
		Network string `json:"network,omitempty"`
		// http request addr
		Addr string `json:"addr,omitempty"`
		// http local addr
		LocalAddr string `json:"localAddr,omitempty"`
		// tcp reused
		Reused bool `json:"reused,omitempty"`
		// tcp was idle
		WasIdle bool `json:"wasIdle,omitempty"`
		// tcp idle time
		IdleTime time.Duration `json:"idleTime,omitempty"`
		// http protocol
		Protocol string `json:"protocol,omitempty"`
		// tls version
		TLSVersion string `json:"tlsVersion,omitempty"`
		// tls resume
		TLSResume bool `json:"tlsResume,omitempty"`
		// tls cipher suite
		TLSCipherSuite string `json:"tlsCipherSuite,omitempty"`
		// tls certificate lst
		Certificates []tlsCertificate `json:"certificates,omitempty"`
		// OCSPStapled OCSP stapling
		OCSPStapled bool `json:"ocspStapled,omitempty"`
		// DNSCoalesced dns query coalesced
		DNSCoalesced bool `json:"dnsCoalesced"`

		// start time of request
		Start time.Time `json:"start,omitempty"`
		// get connection time of request
		GetConn time.Time `json:"getConn,omitempty"`
		// dns start time
		DNSStart time.Time `json:"dnsStart,omitempty"`
		// dns done time
		DNSDone time.Time `json:"dnsDone,omitempty"`
		// connect start time
		ConnectStart time.Time `json:"connectStart,omitempty"`
		// connect done time
		ConnectDone time.Time `json:"connectDone,omitempty"`
		// got connect time
		GotConnect time.Time `json:"gotConnect,omitempty"`
		// wrote headers time
		WroteHeaders time.Time `json:"wroteHeaders,omitempty"`
		// wrote request
		WroteRequest time.Time `json:"wroteRequest,omitempty"`
		// got first response byte time
		GotFirstResponseByte time.Time `json:"gotFirstResponseByte,omitempty"`
		// tls handshake start time
		TLSHandshakeStart time.Time `json:"tlsHandshakeStart,omitempty"`
		// tls handshake done time
		TLSHandshakeDone time.Time `json:"tlsHandshakeDone,omitempty"`
		// unmarshal start time
		UnmarshalStart time.Time `json:"unmarshalStart,omitempty"`
		// unmarshal done time
		UnmarshalDone time.Time `json:"unmarshalDone,omitempty"`
		// request done time
		Done time.Time `json:"done,omitempty"`
	}
)

var (
	versions     map[uint16]string
	cipherSuites map[uint16]string
)

func init() {
	versions = map[uint16]string{
		tls.VersionTLS10: "tls1.0",
		tls.VersionTLS11: "tls1.1",
		tls.VersionTLS12: "tls1.2",
		versionTLS13:     "tls1.3",
	}
	cipherSuites = map[uint16]string{
		// TLS 1.0 - 1.2 cipher suites.
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",

		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

		// TLS 1.3 cipher suites.
		TLS_AES_128_GCM_SHA256:       "TLS_AES_128_GCM_SHA256",
		TLS_AES_256_GCM_SHA384:       "TLS_AES_256_GCM_SHA384",
		TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",

		// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
		// that the client is doing version fallback. See RFC 7507.
		tls.TLS_FALLBACK_SCSV: "TLS_FALLBACK_SCSV",
	}
}

func convertTLSVersion(version uint16) string {
	// 0 则返回-，未知
	if version == 0 {
		return "-"
	}
	v, ok := versions[version]
	if !ok {
		v = strconv.Itoa(int(version))
	}
	return v
}

func convertCipherSuite(cipherSuite uint16) string {
	// 0 则返回-，未知
	if cipherSuite == 0 {
		return "-"
	}
	v, ok := cipherSuites[cipherSuite]
	if !ok {
		v = strconv.Itoa(int(cipherSuite))
	}
	return v
}

// String return http timeline stats's string
func (stats *HTTPTimelineStats) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.GetConnection.String(), "get connection"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.DNSLookup.String(), "dns lookup"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.TCPConnection.String(), "tcp connection"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.TLSHandshake.String(), "tls handshake"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.RequestSend.String(), "request send"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.ServerProcessing.String(), "server processing"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.ContentTransfer.String(), "content transfer"))
	sb.WriteString(fmt.Sprintf("%s(%s)", stats.Total.String(), "total"))
	return sb.String()
}

// Finish http trace
func (ht *HTTPTrace) Finish() {
	ht.Done = time.Now()
}

// Stats returns the stats of time line
func (ht *HTTPTrace) Stats() (stats *HTTPTimelineStats) {
	stats = &HTTPTimelineStats{}
	if !ht.GetConn.IsZero() {
		stats.GetConnection = ht.GetConn.Sub(ht.Start)
	}
	if !ht.DNSStart.IsZero() && !ht.DNSDone.IsZero() {
		stats.DNSLookup = ht.DNSDone.Sub(ht.DNSStart)
	}
	if !ht.ConnectStart.IsZero() && !ht.ConnectDone.IsZero() {
		stats.TCPConnection = ht.ConnectDone.Sub(ht.ConnectStart)
	}
	if !ht.TLSHandshakeStart.IsZero() && !ht.TLSHandshakeDone.IsZero() {
		stats.TLSHandshake = ht.TLSHandshakeDone.Sub(ht.TLSHandshakeStart)
	}

	if !ht.WroteRequest.IsZero() && !ht.GotConnect.IsZero() {
		stats.RequestSend = ht.WroteHeaders.Sub(ht.GotConnect)
	}

	if !ht.WroteRequest.IsZero() && !ht.GotFirstResponseByte.IsZero() {
		stats.ServerProcessing = ht.GotFirstResponseByte.Sub(ht.WroteRequest)
	}
	if ht.Done.IsZero() {
		ht.Done = time.Now()
	}
	if !ht.GotFirstResponseByte.IsZero() {
		stats.ContentTransfer = ht.Done.Sub(ht.GotFirstResponseByte)
	}
	if !ht.UnmarshalDone.IsZero() {
		stats.Unmarshal = ht.UnmarshalDone.Sub(ht.UnmarshalStart)
	}
	stats.Total = ht.Done.Sub(ht.Start)
	return
}

// NewClientTrace returns a new client trace
func NewClientTrace() (trace *httptrace.ClientTrace, ht *HTTPTrace) {
	ht = &HTTPTrace{
		Start: time.Now(),
	}
	trace = &httptrace.ClientTrace{
		DNSStart: func(info httptrace.DNSStartInfo) {
			ht.Host = info.Host
			ht.DNSStart = time.Now()
		},
		DNSDone: func(info httptrace.DNSDoneInfo) {
			ht.Addrs = make([]string, len(info.Addrs))
			for index, addr := range info.Addrs {
				ht.Addrs[index] = addr.String()
			}
			ht.DNSCoalesced = info.Coalesced
			ht.DNSDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			// 在支持ipv6的网络有可能会调用多次
			// 因此仅为0的时候才设置
			if ht.ConnectStart.IsZero() {
				ht.ConnectStart = time.Now()
			}
		},
		ConnectDone: func(network, addr string, _ error) {
			ht.Network = network
			ht.Addr = addr
			if ht.ConnectDone.IsZero() {
				ht.ConnectDone = time.Now()
			}
		},
		GetConn: func(_ string) {
			ht.GetConn = time.Now()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				ht.LocalAddr = info.Conn.LocalAddr().String()
				remoteAddr := info.Conn.RemoteAddr()
				ht.Network = remoteAddr.Network()
				ht.Addr = remoteAddr.String()
			}

			ht.Reused = info.Reused
			ht.WasIdle = info.WasIdle
			ht.IdleTime = info.IdleTime

			ht.GotConnect = time.Now()
		},
		WroteHeaders: func() {
			ht.WroteHeaders = time.Now()
		},
		WroteRequest: func(_ httptrace.WroteRequestInfo) {
			// 如果设置了允许重试，则有可能多次触发
			if ht.WroteRequest.IsZero() {
				ht.WroteRequest = time.Now()
			}
		},
		GotFirstResponseByte: func() {
			ht.GotFirstResponseByte = time.Now()
		},
		TLSHandshakeStart: func() {
			ht.TLSHandshakeStart = time.Now()
		},
		TLSHandshakeDone: func(info tls.ConnectionState, _ error) {
			ht.Certificates = make([]tlsCertificate, 0)
			ht.OCSPStapled = len(info.OCSPResponse) != 0
			for _, item := range info.PeerCertificates {
				if len(item.DNSNames) != 0 {
					ht.Certificates = append(ht.Certificates, tlsCertificate{
						DNSNames:  item.DNSNames,
						NotBefore: item.NotBefore,
						NotAfter:  item.NotAfter,
					})
				}
			}
			ht.TLSVersion = convertTLSVersion(info.Version)
			ht.TLSResume = info.DidResume
			ht.TLSCipherSuite = convertCipherSuite(info.CipherSuite)
			ht.Protocol = info.NegotiatedProtocol

			ht.TLSHandshakeDone = time.Now()
		},
	}
	return
}
