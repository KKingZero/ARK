package ldapcli

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	attrNeverReveal    = "msDS-NeverRevealGroup"
	attrRevealOnDemand = "msDS-RevealOnDemandGroup"
)

// ClearNeverReveal deletes msDS-NeverRevealGroup on the RODC computer object.
func ClearNeverReveal(conn *ldap.Conn, baseDN, rodcSAM string) (string, error) {
	dn, err := rodcDN(conn, baseDN, rodcSAM)
	if err != nil {
		return "", err
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace(attrNeverReveal, []string{})
	if err := conn.Modify(mod); err != nil {
		return dn, fmt.Errorf("clear %s on %s: %w", attrNeverReveal, dn, err)
	}
	return dn, nil
}

// AddRevealOnDemand adds a group's DN to msDS-RevealOnDemandGroup on the RODC.
func AddRevealOnDemand(conn *ldap.Conn, baseDN, rodcSAM, groupSAM string) (string, error) {
	dn, err := rodcDN(conn, baseDN, rodcSAM)
	if err != nil {
		return "", err
	}
	gDN, err := FindDN(conn, baseDN, groupSAM)
	if err != nil {
		return dn, fmt.Errorf("reveal group %q: %w", groupSAM, err)
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Add(attrRevealOnDemand, []string{gDN})
	if err := conn.Modify(mod); err != nil {
		return dn, fmt.Errorf("add %s on %s: %w", attrRevealOnDemand, dn, err)
	}
	return dn, nil
}

const uacPartialSecrets = 0x04000000 // ADS_UF_PARTIAL_SECRETS_ACCOUNT (RODC)

func rodcDN(conn *ldap.Conn, baseDN, sam string) (string, error) {
	sam = strings.TrimSpace(sam)
	if sam == "" {
		return "", fmt.Errorf("--rodc sAMAccountName required")
	}
	if !strings.HasSuffix(sam, "$") {
		sam += "$"
	}
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(sam))
	entries, err := Search(conn, baseDN, filter, []string{"distinguishedName", "userAccountControl"})
	if err != nil {
		return "", fmt.Errorf("RODC %q: %w", sam, err)
	}
	if len(entries) == 0 {
		return "", fmt.Errorf("RODC %q not found", sam)
	}
	uac := 0
	if v := entries[0].GetAttributeValue("userAccountControl"); v != "" {
		fmt.Sscanf(v, "%d", &uac)
	}
	if uac&uacPartialSecrets == 0 {
		return "", fmt.Errorf("%s is not an RODC (missing PARTIAL_SECRETS_ACCOUNT)", sam)
	}
	return entries[0].DN, nil
}
