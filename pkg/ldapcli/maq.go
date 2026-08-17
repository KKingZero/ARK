package ldapcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const maqAttr = "ms-DS-MachineAccountQuota"

// ReadMAQ reads ms-DS-MachineAccountQuota from the domain object.
// ok=false means the attribute was absent (AD default is 10).
func ReadMAQ(conn *ldap.Conn, baseDN string) (n int, ok bool, err error) {
	if conn == nil {
		return 0, false, fmt.Errorf("ldap connection required")
	}
	if baseDN == "" {
		return 0, false, fmt.Errorf("base DN required")
	}
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{maqAttr},
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		return 0, false, fmt.Errorf("MAQ search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return 0, false, fmt.Errorf("MAQ: no domain object at %s", baseDN)
	}
	raw := sr.Entries[0].GetAttributeValue(maqAttr)
	if raw == "" {
		return 0, false, nil
	}
	n, err = ParseMAQ(raw)
	if err != nil {
		return 0, false, err
	}
	return n, true, nil
}

// ParseMAQ parses the LDAP integer (unit-tested without a DC).
func ParseMAQ(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, fmt.Errorf("empty MAQ")
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("MAQ %q: %w", raw, err)
	}
	return n, nil
}
