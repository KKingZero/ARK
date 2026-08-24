package ldapcli

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// SetAllowlist is the v1 host write surface (scriptPath + servicePrincipalName).
var SetAllowlist = map[string]string{
	"scriptpath":           "scriptPath",
	"script_path":          "scriptPath",
	"serviceprincipalname": "servicePrincipalName",
	"spn":                  "servicePrincipalName",
}

// CanonicalSetAttr maps operator aliases onto the LDAP attribute name.
func CanonicalSetAttr(name string) (string, error) {
	k := strings.ToLower(strings.TrimSpace(name))
	if a, ok := SetAllowlist[k]; ok {
		return a, nil
	}
	if k == "scriptpath" {
		return "scriptPath", nil
	}
	return "", fmt.Errorf("attribute %q not allowlisted (v1: scriptPath, servicePrincipalName)", name)
}

// SetAttr replaces one allowlisted attribute on the object identified by sAMAccountName.
func SetAttr(conn *ldap.Conn, baseDN, sam, attr, value string) error {
	if conn == nil {
		return fmt.Errorf("ldap conn required")
	}
	canon, err := CanonicalSetAttr(attr)
	if err != nil {
		return err
	}
	sam = strings.TrimSpace(sam)
	if sam == "" {
		return fmt.Errorf("target sAMAccountName required")
	}
	dn, err := FindDN(conn, baseDN, sam)
	if err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(dn, nil)
	if value == "" {
		mod.Replace(canon, []string{})
	} else {
		mod.Replace(canon, []string{value})
	}
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("ldap set %s on %s: %w", canon, dn, err)
	}
	return nil
}

// FindDN resolves sAMAccountName → distinguishedName.
func FindDN(conn *ldap.Conn, baseDN, sam string) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("ldap conn required")
	}
	if baseDN == "" || sam == "" {
		return "", fmt.Errorf("base DN and sAMAccountName required")
	}
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(sam))
	entries, err := Search(conn, baseDN, filter, []string{"distinguishedName", "sAMAccountName"})
	if err != nil {
		return "", err
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("object %q not found", sam)
	}
	return entries[0].DN, nil
}
