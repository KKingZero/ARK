// Package netproxy dials TCP through ALL_PROXY / EREBUS_PROXY (SOCKS5).
// Host-side ldap/smb/kerberos use this so they can reach a DC via C implant SOCKS.
package netproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

const defaultTimeout = 15 * time.Second

// ProxyEnv returns the configured SOCKS/HTTP proxy URL, or empty.
// Precedence: EREBUS_PROXY, ALL_PROXY, all_proxy.
func ProxyEnv() string {
	for _, k := range []string{"EREBUS_PROXY", "ALL_PROXY", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// SkipProxy reports whether address should bypass the proxy (loopback).
// Set EREBUS_PROXY_LOCAL=1 to force proxying localhost (tests).
func SkipProxy(address string) bool {
	if os.Getenv("EREBUS_PROXY_LOCAL") == "1" {
		return false
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	host = strings.Trim(host, "[]")
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return true
	}
	return false
}

// DialTimeout is net.DialTimeout that honors SOCKS5 from ProxyEnv.
func DialTimeout(network, address string, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	raw := ProxyEnv()
	if raw == "" || SkipProxy(address) {
		return net.DialTimeout(network, address, timeout)
	}
	return dialProxy(raw, network, address, timeout)
}

func dialProxy(raw, network, address string, timeout time.Duration) (net.Conn, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", raw, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "socks":
	default:
		return nil, fmt.Errorf("proxy %s: only socks5 supported (got %q)", raw, u.Scheme)
	}
	d, err := proxy.FromURL(u, &net.Dialer{Timeout: timeout})
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", raw, err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c, err := cd.DialContext(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("proxy %s: %w", u.Host, err)
		}
		return c, nil
	}
	c, err := d.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", u.Host, err)
	}
	return c, nil
}
