package krb

import (
	"fmt"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// FetchDCTime queries the DC root DSE for currentTime (LDAP GeneralizedTime).
// host is host:port or host (defaults to 389). Anonymous bind is tried first;
// if bindDN/password are set, simple bind is used.
func FetchDCTime(host string, bindDN, password string) (time.Time, error) {
	if host == "" {
		return time.Time{}, fmt.Errorf("dc host required")
	}
	addr := host
	// go-ldap DialURL prefers ldap://
	url := addr
	if len(addr) < 8 || (addr[:7] != "ldap://" && addr[:8] != "ldaps://") {
		// host or host:port
		url = "ldap://" + addr
	}
	conn, err := ldap.DialURL(url)
	if err != nil {
		return time.Time{}, fmt.Errorf("ldap dial %s: %w", url, err)
	}
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
	raw := res.Entries[0].GetAttributeValue("currentTime")
	if raw == "" {
		return time.Time{}, fmt.Errorf("ldap rootDSE: empty currentTime")
	}
	return ParseLDAPGeneralizedTime(raw)
}

// CheckSkewVsDC fetches DC time and compares to local clock.
func CheckSkewVsDC(host string, bindDN, password string, maxSkew time.Duration) (SkewResult, error) {
	remote, err := FetchDCTime(host, bindDN, password)
	if err != nil {
		return SkewResult{}, err
	}
	return Compare(time.Now(), remote, maxSkew), nil
}
