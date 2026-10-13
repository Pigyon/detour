package client

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// browserProfile pairs a TLS client hello with the HTTP headers a real browser
// sends, so both the TLS fingerprint and the request surface match.
type browserProfile struct {
	helloID utls.ClientHelloID
	headers http.Header
}

var browserProfiles = map[string]browserProfile{
	"chrome": {
		helloID: utls.HelloChrome_Auto,
		headers: http.Header{
			"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"},
			"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"},
			"Accept-Language":           {"en-US,en;q=0.9"},
			"Sec-Ch-Ua":                 {`"Chromium";v="131", "Not_A Brand";v="24"`},
			"Sec-Ch-Ua-Mobile":          {"?0"},
			"Sec-Ch-Ua-Platform":        {`"Windows"`},
			"Upgrade-Insecure-Requests": {"1"},
		},
	},
	"firefox": {
		helloID: utls.HelloFirefox_Auto,
		headers: http.Header{
			"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"},
			"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
			"Accept-Language":           {"en-US,en;q=0.5"},
			"Upgrade-Insecure-Requests": {"1"},
		},
	},
}

// resolveBrowserProfile returns the profile for name, or nil when TLS
// impersonation is not requested. An unknown name is an error.
func resolveBrowserProfile(name string) (*browserProfile, error) {
	if name == "" {
		return nil, nil
	}

	p, ok := browserProfiles[strings.ToLower(name)]
	if !ok {
		avail := make([]string, 0, len(browserProfiles))
		for k := range browserProfiles {
			avail = append(avail, k)
		}

		return nil, fmt.Errorf("unknown --tls-impersonate %q (available: %s)", name, strings.Join(avail, ", "))
	}

	return &p, nil
}

// applyBrowserDefaults fills in browser-like headers for any name not already
// set on the request. Explicit --header values and credentials win because
// they are applied first.
func applyBrowserDefaults(req *http.Request, defaults http.Header) {
	if defaults == nil {
		return
	}

	for name, values := range defaults {
		if req.Header.Get(name) != "" {
			continue
		}

		for _, v := range values {
			req.Header.Add(name, v)
		}
	}
}

// makeUTLSDialer returns a DialTLSContext function that impersonates a
// browser's TLS fingerprint. When proxyURL is non-nil it tunnels through
// an HTTP CONNECT proxy first, so the target sees the impersonated
// fingerprint rather than Go's default one.
func makeUTLSDialer(
	proxyURL *url.URL,
	helloID utls.ClientHelloID,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var (
			rawConn net.Conn
			err     error
		)

		if proxyURL != nil {
			rawConn, err = dialCONNECT(ctx, proxyURL, addr)
		} else {
			rawConn, err = (&net.Dialer{}).DialContext(ctx, network, addr)
		}

		if err != nil {
			return nil, err
		}

		return utlsHandshake(ctx, rawConn, addr, helloID)
	}
}

func utlsHandshake(ctx context.Context, rawConn net.Conn, addr string, helloID utls.ClientHelloID) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("splitting host:port %q: %w", addr, err)
	}

	// The browser presets advertise h2 ahead of http/1.1 in ALPN, and a server
	// that picks h2 then speaks HTTP/2 frames that Go's HTTP/1.1 transport (the
	// one DialTLSContext feeds) cannot parse. Forcing ALPN to http/1.1 avoids
	// that without touching the JA3 fingerprint: JA3 hashes the extension's
	// type id, not the protocol list inside it, so the hello still looks like
	// the browser's.
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("resolving utls spec: %w", err)
	}

	for _, ext := range spec.Extensions {
		if alpn, ok := ext.(*utls.ALPNExtension); ok {
			alpn.AlpnProtocols = []string{"http/1.1"}
		}
	}

	uconn := utls.UClient(rawConn, &utls.Config{ServerName: host}, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("applying utls spec: %w", err)
	}

	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("utls handshake with %s: %w", host, err)
	}

	return uconn, nil
}

// dialCONNECT establishes an HTTP CONNECT tunnel through a proxy so that
// DialTLSContext can layer a utls handshake on top of the raw tunnel.
func dialCONNECT(ctx context.Context, proxyURL *url.URL, targetAddr string) (net.Conn, error) {
	proxyHost := proxyURL.Host

	if _, _, splitErr := net.SplitHostPort(proxyHost); splitErr != nil {
		port := "80"
		if proxyURL.Scheme == "https" {
			port = "443"
		}

		proxyHost = net.JoinHostPort(proxyHost, port)
	}

	rawConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("dialing proxy %s: %w", proxyHost, err)
	}

	var buf strings.Builder

	fmt.Fprintf(&buf, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)

	if proxyURL.User != nil {
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

		fmt.Fprintf(&buf, "Proxy-Authorization: Basic %s\r\n", cred)
	}

	buf.WriteString("\r\n")

	if _, writeErr := rawConn.Write([]byte(buf.String())); writeErr != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("writing CONNECT: %w", writeErr)
	}

	br := bufio.NewReader(rawConn)

	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = rawConn.Close()

		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}

	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = rawConn.Close()

		return nil, fmt.Errorf("proxy CONNECT %s: %s", targetAddr, resp.Status)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: rawConn, reader: br}, nil
	}

	return rawConn, nil
}

// httpOnlyProxy returns a proxy function that applies only to HTTP (non-TLS)
// requests. HTTPS is handled by DialTLSContext with utls, so the transport's
// built-in proxy mechanism must not intercept it.
func httpOnlyProxy(u *url.URL) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if req.URL.Scheme == "https" {
			return nil, nil
		}

		return u, nil
	}
}

// bufferedConn wraps a net.Conn with a bufio.Reader that may hold bytes read
// ahead past the CONNECT response.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
