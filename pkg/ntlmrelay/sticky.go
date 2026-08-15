package ntlmrelay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
)

// stickyConn wraps a TCP connection and ignores Close so http.Transport
// cannot drop the socket mid-NTLM (connection-oriented auth).
type stickyConn struct {
	net.Conn
	mu     sync.Mutex
	closed bool
}

func (c *stickyConn) Close() error {
	// no-op for Transport; use RealClose when the session ends
	return nil
}

func (c *stickyConn) RealClose() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.Conn.Close()
}

// stickyTransport pins all requests to a single dialed connection to the target host.
type stickyTransport struct {
	mu      sync.Mutex
	baseURL *url.URL
	conn    *stickyConn
	rt      http.RoundTripper // underlying once conn is ready
	insecure bool
}

func newStickyTransport(target *url.URL, insecure bool) *stickyTransport {
	return &stickyTransport{baseURL: target, insecure: insecure}
}

func (t *stickyTransport) ensure() (http.RoundTripper, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.rt != nil {
		return t.rt, nil
	}
	host := t.baseURL.Host
	if _, _, err := net.SplitHostPort(host); err != nil {
		// add default port
		if t.baseURL.Scheme == "https" {
			host = net.JoinHostPort(t.baseURL.Hostname(), "443")
		} else {
			host = net.JoinHostPort(t.baseURL.Hostname(), "80")
		}
	}
	d := net.Dialer{Timeout: 30 * time.Second}
	raw, err := d.DialContext(context.Background(), "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("sticky dial %s: %w", host, err)
	}
	var conn net.Conn = raw
	if t.baseURL.Scheme == "https" {
		cfg := &tls.Config{
			ServerName:         t.baseURL.Hostname(),
			InsecureSkipVerify: t.insecure, //nolint:gosec // lab opt-in
		}
		tc := tls.Client(raw, cfg)
		if err := tc.Handshake(); err != nil {
			_ = raw.Close()
			return nil, fmt.Errorf("tls handshake: %w", err)
		}
		conn = tc
	}
	sc := &stickyConn{Conn: conn}
	t.conn = sc
	tr := &http.Transport{
		// Always return the same conn; ignore network/addr.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sc, nil
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Already TLS-wrapped if needed.
			return sc, nil
		},
		MaxIdleConns:        1,
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     5 * time.Minute,
		DisableKeepAlives:   false,
		// Force HTTP/1.1 single connection semantics.
		ForceAttemptHTTP2: false,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: t.insecure, //nolint:gosec
			ServerName:         t.baseURL.Hostname(),
		},
	}
	// For https, DialTLSContext returns already-handshaken conn; Transport may try TLS again.
	// Prefer plain DialContext-only for both: we pre-wrap TLS above and set scheme handling
	// by using http URL with custom dial that returns TLS conn — actually Transport for https
	// always uses DialTLSContext. Our DialTLSContext returns sc which is already TLS.
	// Disable TLSClientConfig handshake by using http scheme with TLS conn? Messy.
	//
	// Cleaner: only use DialContext and request URL as http:// even for TLS... no.
	// Use: scheme https + DialTLSContext returning pre-handshaked stickyConn.
	t.rt = tr
	return tr, nil
}

func (t *stickyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt, err := t.ensure()
	if err != nil {
		return nil, err
	}
	return rt.RoundTrip(req)
}

func (t *stickyTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn != nil {
		return t.conn.RealClose()
	}
	return nil
}

// newTargetClient builds an HTTP client that keeps one sticky connection to target.
// Redirects never forward Authorization (NTLM blob leak prevention).
func newTargetClient(targetURL string, insecure bool) (*http.Client, *stickyTransport, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, err
	}
	st := newStickyTransport(u, insecure)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{
		// No global Timeout — large LFI downloads; callers may cancel via context later.
		Jar:       jar,
		Transport: st,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			// Never forward NTLM Authorization to a different host (or any redirect).
			req.Header.Del("Authorization")
			// Prefer not following off-target hosts
			if len(via) > 0 && req.URL.Host != via[0].URL.Host {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return c, st, nil
}
