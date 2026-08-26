// SPDX-License-Identifier: LGPL-3.0-or-later

package truenas

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// UnixSocketPrefix is the URI scheme for connecting to a local
	// middlewared UNIX domain socket.
	UnixSocketPrefix = "ws+unix://"

	// MiddlewareRunDir is the directory containing the middlewared UNIX
	// domain socket.
	MiddlewareRunDir = "/run/middleware"

	// DummyHostname is used for the websocket handshake over transports
	// where the URL carries no real host (advised by the official docs).
	dummyHostname = "ws://localhost/api/current"

	dialTimeout = 10 * time.Second
)

// dialWebsocket establishes the websocket connection for uri, honoring the
// unix-socket and reserved-port transports (ports WSClient.connect from the
// Python client).
func dialWebsocket(ctx context.Context, uri string, reservedPorts, verifySSL bool) (*websocket.Conn, error) {
	dialer := websocket.Dialer{
		HandshakeTimeout: dialTimeout,
	}
	handshakeURL := uri

	switch {
	case strings.HasPrefix(uri, UnixSocketPrefix):
		path := strings.TrimPrefix(uri, UnixSocketPrefix)
		dialer.NetDialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
		handshakeURL = dummyHostname

	case reservedPorts:
		// reservedPorts uses a plain TCP socket and never negotiates TLS,
		// so it only supports a plaintext ws:// URI. Require that scheme
		// explicitly rather than, for example, connecting a wss:// URI in
		// cleartext.
		parsed, err := url.Parse(uri)
		if err != nil {
			return nil, &ClientError{Reason: fmt.Sprintf("invalid URI %q: %v", uri, err)}
		}
		if parsed.Scheme != "ws" {
			return nil, &ClientError{
				Reason: fmt.Sprintf("reserved_ports connections require a ws:// URI, got %q", parsed.Scheme),
			}
		}
		dialer.NetDialContext = dialFromReservedPort
		handshakeURL = uri

	default:
		if !verifySSL {
			dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		}
		dialer.NetDialContext = keepaliveDialer().DialContext
	}

	conn, resp, err := dialer.DialContext(ctx, handshakeURL, nil)
	if err != nil {
		if resp != nil {
			return nil, &ClientError{Reason: fmt.Sprintf("websocket handshake to %s failed: %v (HTTP %d)", uri, err, resp.StatusCode)}
		}
		return nil, &ClientError{Reason: fmt.Sprintf("websocket connection to %s failed: %v", uri, err)}
	}
	return conn, nil
}

// keepaliveDialer returns a net.Dialer with aggressive TCP keepalives: if the
// other node panics, the socket would otherwise stay open until the default
// TCP timeout expires. Probe after 1s idle, every 1s, up to 5 times.
func keepaliveDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: dialTimeout,
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     time.Second,
			Interval: time.Second,
			Count:    5,
		},
	}
}

// dialFromReservedPort connects to addr from a local port in the privileged
// 600-1024 range. Linux has no mechanism for the kernel to dynamically assign
// ports in that range, so bind explicitly, trying 5 distinct random ports
// (requires the process to run as root).
func dialFromReservedPort(ctx context.Context, network, addr string) (net.Conn, error) {
	const portLow, portHigh = 600, 1024

	ports := rand.Perm(portHigh - portLow)[:5]
	var lastErr error
	for _, offset := range ports {
		d := keepaliveDialer()
		d.LocalAddr = &net.TCPAddr{Port: portLow + offset}
		conn, err := d.DialContext(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, &ClientError{Reason: fmt.Sprintf("failed to bind to a reserved port: %v", lastErr)}
}

// peerCertificateDER returns the server's TLS certificate in DER form, or nil
// for a non-TLS transport (unix socket, plain ws://, or reserved-port
// connection). Used to compute the RFC 5929 tls-server-end-point SCRAM
// channel binding; the certificate is retrievable even when SSL verification
// is disabled.
func peerCertificateDER(conn *websocket.Conn) []byte {
	if tlsConn, ok := conn.NetConn().(*tls.Conn); ok {
		certs := tlsConn.ConnectionState().PeerCertificates
		if len(certs) > 0 {
			return certs[0].Raw
		}
	}
	return nil
}
