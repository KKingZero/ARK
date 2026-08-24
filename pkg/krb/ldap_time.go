package krb

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/netproxy"
	"github.com/go-ldap/ldap/v3"
)

// FetchDCTime queries the DC root DSE for currentTime (LDAP GeneralizedTime).
// host is host:port, host, ldap://, or ldaps:// (TLS + 636). Anonymous bind
// is tried first; if bindDN/password are set, simple bind is used.
func FetchDCTime(host string, bindDN, password string) (time.Time, error) {
	if host == "" {
		return time.Time{}, fmt.Errorf("dc host required")
	}
	addr, useTLS, serverName := ldapDialTarget(host)
	raw, err := netproxy.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return time.Time{}, fmt.Errorf("ldap dial %s: %w", addr, err)
	}
	var conn *ldap.Conn
	if useTLS {
		tlsConn := tls.Client(raw, &tls.Config{
			InsecureSkipVerify: true, // lab DC certs
			MinVersion:         tls.VersionTLS12,
			ServerName:         serverName,
		})
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return time.Time{}, fmt.Errorf("ldaps handshake %s: %w", addr, err)
		}
		conn = ldap.NewConn(tlsConn, true)
	} else {
		conn = ldap.NewConn(raw, false)
	}
	conn.Start()
	defer conn.Close()

	if bindDN != "" {
		if err := conn.Bind(bindDN, password); err != nil {
			return time.Time{}, fmt.Errorf("ldap bind: %w", err)
		}
	} else {
		// anonymous
		_ = conn.UnauthenticatedBind("")
	}

	req := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 10, false,
		"(objectClass=*)",
		[]string{"currentTime"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("ldap rootDSE search: %w", err)
	}
	if len(res.Entries) == 0 {
		return time.Time{}, fmt.Errorf("ldap rootDSE: no entries")
	}
	cur := res.Entries[0].GetAttributeValue("currentTime")
	if cur == "" {
		return time.Time{}, fmt.Errorf("ldap rootDSE: empty currentTime")
	}
	return ParseLDAPGeneralizedTime(cur)
}

func ldapDialAddr(host string) string {
	addr, _, _ := ldapDialTarget(host)
	return addr
}

func ldapDialTarget(host string) (addr string, useTLS bool, serverName string) {
	host = strings.TrimSpace(host)
	if strings.HasPrefix(strings.ToLower(host), "ldaps://") {
		useTLS = true
		host = host[8:]
	} else if strings.HasPrefix(strings.ToLower(host), "ldap://") {
		host = host[7:]
	}
	def := "389"
	if useTLS {
		def = "636"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "" {
			p = def
		}
		return net.JoinHostPort(h, p), useTLS, h
	}
	return net.JoinHostPort(host, def), useTLS, host
}

// CheckSkewVsDC fetches DC time and compares to local clock.
func CheckSkewVsDC(host string, bindDN, password string, maxSkew time.Duration) (SkewResult, error) {
	remote, err := FetchDCTime(host, bindDN, password)
	if err != nil {
		return SkewResult{}, err
	}
	return Compare(time.Now(), remote, maxSkew), nil
}
