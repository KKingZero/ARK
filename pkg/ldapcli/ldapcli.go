// Package ldapcli is a host-side LDAP client (no implant session).
// Lab/HTB: prefers LDAPS so DCs that require signing (strongerAuthRequired) still bind.
package ldapcli

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/netproxy"
	"github.com/go-ldap/ldap/v3"
)

const (
	dialTimeout      = 15 * time.Second
	maxSearchEntries = 5000
)

// Options for an authenticated (or anonymous) LDAP bind.
type Options struct {
	Host     string
	Domain   string
	Username string
	Password string
	Hash     string // NT hash hex (32) or LM:NT
	// Port overrides the default (636 if PreferLDAPS, else 389).
	Port int
	// PreferLDAPS is true by default for host-side binds.
	PreferLDAPS bool
	// RequireTLS refuses the plaintext 389 fallback (password set must use this).
	RequireTLS bool
	// InsecureSkipVerify is true by default (lab self-signed DC certs).
	InsecureSkipVerify bool
}

// DefaultOptions returns lab defaults (LDAPS, skip verify).
func DefaultOptions() Options {
	return Options{PreferLDAPS: true, InsecureSkipVerify: true}
}

// BaseDN converts example.htb → DC=example,DC=htb.
func BaseDN(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	parts := strings.Split(domain, ".")
	dcs := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		if !validDNSLabel(p) {
			return ""
		}
		dcs = append(dcs, "DC="+p)
	}
	return strings.Join(dcs, ",")
}

func validDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			continue
		}
		if r == '-' && i > 0 && i < len(s)-1 {
			continue
		}
		return false
	}
	return true
}

// SplitUser returns NTLM domain and sAM from DOMAIN\user, user@domain, or bare user.
func SplitUser(username, domain string) (dom, user string) {
	user = username
	dom = domain
	if strings.Contains(username, `\`) {
		parts := strings.SplitN(username, `\`, 2)
		return parts[0], parts[1]
	}
	if strings.Contains(username, "@") {
		parts := strings.SplitN(username, "@", 2)
		return parts[1], parts[0]
	}
	if dom != "" && strings.Contains(dom, ".") {
		dom = strings.SplitN(dom, ".", 2)[0]
	}
	return dom, user
}

// NormalizeHash returns 32-char NT hex for NTLMBindWithHash.
func NormalizeHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		hash = parts[len(parts)-1]
	}
	if len(hash) == 64 {
		hash = hash[32:]
	}
	return strings.ToLower(hash)
}

// Bind opens LDAP and authenticates. Tries LDAPS first, then TCP 389 NTLM.
func Bind(opts Options) (*ldap.Conn, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("host required")
	}
	preferTLS := opts.PreferLDAPS || opts.RequireTLS || opts.Port == 636
	var tlsErr error
	if preferTLS {
		conn, err := dialLDAPS(opts)
		if err != nil {
			tlsErr = err
		} else if err := authenticate(conn, opts); err != nil {
			conn.Close()
			tlsErr = err
		} else {
			return conn, nil
		}
	}
	if opts.RequireTLS {
		if tlsErr != nil {
			return nil, fmt.Errorf("ldaps required: %w", tlsErr)
		}
		return nil, fmt.Errorf("ldaps required")
	}
	conn, err := dialLDAP(opts)
	if err != nil {
		if tlsErr != nil {
			return nil, fmt.Errorf("%v; ldap: %w", tlsErr, err)
		}
		return nil, err
	}
	if err := authenticate(conn, opts); err != nil {
		conn.Close()
		if tlsErr != nil {
			return nil, fmt.Errorf("ldaps: %v; ldap: %w", tlsErr, err)
		}
		return nil, err
	}
	return conn, nil
}

func dialLDAPS(opts Options) (*ldap.Conn, error) {
	host, port := splitHostPort(opts.Host, 636)
	if opts.Port != 0 {
		port = opts.Port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	tlsCfg := &tls.Config{
		InsecureSkipVerify: opts.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
		ServerName:         host,
	}
	raw, err := netproxy.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ldaps %s: %w", addr, err)
	}
	tlsConn := tls.Client(raw, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("ldaps handshake %s: %w", addr, err)
	}
	conn := ldap.NewConn(tlsConn, true)
	conn.Start()
	return conn, nil
}

func dialLDAP(opts Options) (*ldap.Conn, error) {
	host, port := splitHostPort(opts.Host, 389)
	if opts.Port != 0 && opts.Port != 636 {
		port = opts.Port
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	raw, err := netproxy.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("ldap %s: %w", addr, err)
	}
	conn := ldap.NewConn(raw, false)
	conn.Start()
	return conn, nil
}

func authenticate(conn *ldap.Conn, opts Options) error {
	if opts.Username == "" && opts.Password == "" && opts.Hash == "" {
		// Leave the connection unbound. Fake "success" after a failed
		// UnauthenticatedBind made enum look connected when it was not.
		return nil
	}
	if opts.Username == "" {
		return fmt.Errorf("username required")
	}
	domain, user := SplitUser(opts.Username, opts.Domain)
	if opts.Hash != "" {
		if err := conn.NTLMBindWithHash(domain, user, NormalizeHash(opts.Hash)); err != nil {
			return fmt.Errorf("LDAP NTLM hash bind: %w", err)
		}
		return nil
	}
	if opts.Password == "" {
		return fmt.Errorf("password or hash required")
	}
	// Simple bind (UPN) then NTLM — NTLM is what modern DCs accept.
	upn := user
	if !strings.Contains(upn, "@") && opts.Domain != "" {
		upn = user + "@" + opts.Domain
	}
	if err := conn.Bind(upn, opts.Password); err == nil {
		return nil
	}
	if err := conn.NTLMBind(domain, user, opts.Password); err != nil {
		return fmt.Errorf("LDAP bind: %w", err)
	}
	return nil
}

func splitHostPort(host string, defPort int) (string, int) {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "ldaps://")
	host = strings.TrimPrefix(host, "ldap://")
	// name:port or [v6]:port
	if h, p, err := net.SplitHostPort(host); err == nil {
		port, convErr := strconv.Atoi(p)
		if convErr != nil || port == 0 {
			port = defPort
		}
		return h, port
	}
	// Bare IPv6 has multiple colons and no brackets — not a port suffix.
	return host, defPort
}

// Search is a subtree search; empty base uses domain BaseDN.
func Search(conn *ldap.Conn, base, filter string, attrs []string) ([]*ldap.Entry, error) {
	if filter == "" {
		filter = "(objectClass=*)"
	}
	if len(attrs) == 0 {
		attrs = []string{"*"}
	}
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		maxSearchEntries, 30, false,
		filter,
		attrs,
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LDAP search: %w", err)
	}
	return sr.Entries, nil
}

// RootDSEAttr reads a single rootDSE attribute (e.g. configurationNamingContext).
func RootDSEAttr(conn *ldap.Conn, name string) (string, error) {
	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=*)",
		[]string{name},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		return "", err
	}
	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("rootDSE empty")
	}
	return sr.Entries[0].GetAttributeValue(name), nil
}
