package krb

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/netproxy"
	"github.com/go-ldap/ldap/v3"
)

// FetchDCTime queries the DC root DSE for currentTime (LDAP GeneralizedTime).
// host is host:port or host (defaults to 389). Anonymous bind is tried first;
// if bindDN/password are set, simple bind is used. Honors ALL_PROXY / EREBUS_PROXY.
func FetchDCTime(host string, bindDN, password string) (time.Time, error) {
	if host == "" {
		return time.Time{}, fmt.Errorf("dc host required")
	}
	addr := ldapDialAddr(host)
	raw, err := netproxy.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return time.Time{}, fmt.Errorf("ldap dial %s: %w", addr, err)
	}
	conn := ldap.NewConn(raw, false)
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
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "ldaps://")
	host = strings.TrimPrefix(host, "ldap://")
	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "" {
			p = "389"
		}
		return net.JoinHostPort(h, p)
	}
	return net.JoinHostPort(host, "389")
}

// CheckSkewVsDC fetches DC time and compares to local clock.
func CheckSkewVsDC(host string, bindDN, password string, maxSkew time.Duration) (SkewResult, error) {
	remote, err := FetchDCTime(host, bindDN, password)
	if err != nil {
		return SkewResult{}, err
	}
	return Compare(time.Now(), remote, maxSkew), nil
}
