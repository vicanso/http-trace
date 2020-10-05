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
	nht "net/http/httptrace"
	"strconv"
	"strings"
	"time"
)

type (
	// HTTPTimelineStats http timeline stats
	HTTPTimelineStats struct {
		DNSLookup        time.Duration `json:"dnsLookup,omitempty"`
		GetConnection    time.Duration `json:"getConnection,omitempty"`
		TCPConnection    time.Duration `json:"tcpConnection,omitempty"`
		TLSHandshake     time.Duration `json:"tlsHandshake,omitempty"`
		ServerProcessing time.Duration `json:"serverProcessing,omitempty"`
		ContentTransfer  time.Duration `json:"contentTransfer,omitempty"`
		Total            time.Duration `json:"total,omitempty"`
	}

	tlsCertificate struct {
		DNSNames  []string  `json:"dnsNames,omitempty"`
		NotBefore time.Time `json:"notBefore,omitempty"`
		NotAfter  time.Time `json:"notAfter,omitempty"`
	}

	// HTTPTrace http trace
	HTTPTrace struct {
		// Host request host
		Host           string           `json:"host,omitempty"`
		Addrs          []string         `json:"addrs,omitempty"`
		Network        string           `json:"network,omitempty"`
		Addr           string           `json:"addr,omitempty"`
		LocalAddr      string           `json:"localAddr,omitempty"`
		Reused         bool             `json:"reused,omitempty"`
		WasIdle        bool             `json:"wasIdle,omitempty"`
		IdleTime       time.Duration    `json:"idleTime,omitempty"`
		Protocol       string           `json:"protocol,omitempty"`
		TLSVersion     string           `json:"tlsVersion,omitempty"`
		TLSResume      bool             `json:"tlsResume,omitempty"`
		TLSCipherSuite string           `json:"tlsCipherSuite,omitempty"`
		Certificates   []tlsCertificate `json:"certificates,omitempty"`
		// OCSPStapled OCSP stapling
		OCSPStapled bool `json:"ocspStapled,omitempty"`

		Start                time.Time `json:"start,omitempty"`
		GetConn              time.Time `json:"getConn,omitempty"`
		DNSStart             time.Time `json:"dnsStart,omitempty"`
		DNSDone              time.Time `json:"dnsDone,omitempty"`
		ConnectStart         time.Time `json:"connectStart,omitempty"`
		ConnectDone          time.Time `json:"connectDone,omitempty"`
		GotConnect           time.Time `json:"gotConnect,omitempty"`
		WroteHeaders         time.Time `json:"wroteHeaders,omitempty"`
		GotFirstResponseByte time.Time `json:"gotFirstResponseByte,omitempty"`
		TLSHandshakeStart    time.Time `json:"tlsHandshakeStart,omitempty"`
		TLSHandshakeDone     time.Time `json:"tlsHandshakeDone,omitempty"`
		Done                 time.Time `json:"done,omitempty"`
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
	v, ok := versions[version]
	if !ok {
		v = strconv.Itoa(int(version))
	}
	return v
}

func convertCipherSuite(cipherSuite uint16) string {
	v, ok := cipherSuites[cipherSuite]
	if !ok {
		v = strconv.Itoa(int(cipherSuite))
	}
	return v
}

// String http timeline stats to string
func (stats *HTTPTimelineStats) String() string {
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.DNSLookup.String(), "dns lookup"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.GetConnection.String(), "get connection"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.TCPConnection.String(), "tcp connection"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.TLSHandshake.String(), "tls handshake"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.ServerProcessing.String(), "server processing"))
	sb.WriteString(fmt.Sprintf("%s(%s), ", stats.ContentTransfer.String(), "content transfer"))
	sb.WriteString(fmt.Sprintf("%s(%s)", stats.Total.String(), "total"))
	return sb.String()
}

// Finish http trace finish
func (ht *HTTPTrace) Finish() {
	ht.Done = time.Now()
}

// Stats get the stats of time line
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

	if !ht.GotConnect.IsZero() && !ht.GotFirstResponseByte.IsZero() {
		stats.ServerProcessing = ht.GotFirstResponseByte.Sub(ht.GotConnect)
	}
	if ht.Done.IsZero() {
		ht.Done = time.Now()
	}
	if !ht.GotFirstResponseByte.IsZero() {
		stats.ContentTransfer = ht.Done.Sub(ht.GotFirstResponseByte)
	}
	stats.Total = ht.Done.Sub(ht.Start)
	return
}

// NewClientTrace http client trace
func NewClientTrace() (trace *httptrace.ClientTrace, ht *HTTPTrace) {
	ht = &HTTPTrace{
		Start: time.Now(),
	}
	trace = &httptrace.ClientTrace{
		DNSStart: func(info nht.DNSStartInfo) {
			ht.Host = info.Host
			ht.DNSStart = time.Now()
		},
		DNSDone: func(info nht.DNSDoneInfo) {
			ht.Addrs = make([]string, len(info.Addrs))
			for index, addr := range info.Addrs {
				ht.Addrs[index] = addr.String()
			}
			ht.DNSDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			ht.ConnectStart = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			ht.ConnectDone = time.Now()
		},
		GetConn: func(_ string) {
			ht.GetConn = time.Now()
		},
		GotConn: func(info nht.GotConnInfo) {
			if info.Conn != nil {
				remoteAddr := info.Conn.RemoteAddr()
				ht.Network = remoteAddr.Network()
				ht.Addr = remoteAddr.String()
				ht.LocalAddr = info.Conn.LocalAddr().String()
			}

			ht.Reused = info.Reused
			ht.WasIdle = info.WasIdle
			ht.IdleTime = info.IdleTime

			ht.GotConnect = time.Now()
		},
		WroteHeaders: func() {
			ht.WroteHeaders = time.Now()
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
