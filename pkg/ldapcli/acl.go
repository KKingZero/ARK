package ldapcli

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// ADS / WinNT access bits we care about on AD objects.
const (
	RightGenericAll    = 0x10000000
	RightGenericWrite  = 0x40000000
	RightWriteDACL     = 0x00040000
	RightWriteOwner    = 0x00080000
	RightWriteProperty = 0x00000020
	RightControlAccess = 0x00000100
)

const (
	// GUIDForceChangePassword is User-Force-Change-Password (extended right).
	GUIDForceChangePassword = "00299570-246d-11d0-a768-00aa006e0529"
	// GUIDAllowedToAct is msDS-AllowedToActOnBehalfOfOtherIdentity.
	GUIDAllowedToAct = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"
)

const (
	seDACLPresent     = 0x0004
	seSelfRelative    = 0x8000
	aceAllowed        = 0x00
	aceAllowedObject  = 0x05
	objectTypePresent = 0x00000001
)

// SDFlagsOwnerDACL requests owner + DACL (not SACL) on nTSecurityDescriptor.
const SDFlagsOwnerDACL int32 = 0x05

// ACEFinding is one interesting ACE on an object.
type ACEFinding struct {
	TrusteeSID string
	Trustee    string // well-known name when we have one
	Rights     []string
	ObjectGUID string
}

// ObjectACL is a host-side ACL summary for one AD object.
type ObjectACL struct {
	DN       string
	SAM      string
	Category string // user | computer | group
	OwnerSID string
	Findings []ACEFinding
}

// SearchACL enumerates user/computer/group objects and returns those with
// dangerous DACL rights. Expected privileged trustees (DA/EA/BA/SYSTEM) are
// omitted unless includePrivileged is set.
func SearchACL(conn *ldap.Conn, base string, includePrivileged bool) ([]ObjectACL, error) {
	if conn == nil {
		return nil, fmt.Errorf("ldap conn required")
	}
	if base == "" {
		return nil, fmt.Errorf("base DN required")
	}
	filter := `(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer)(objectCategory=group))`
	attrs := []string{"sAMAccountName", "distinguishedName", "objectCategory", "objectClass", "nTSecurityDescriptor"}
	req := ldap.NewSearchRequest(
		base,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		maxSearchEntries, 60, false,
		filter,
		attrs,
		[]ldap.Control{&ldap.ControlMicrosoftSDFlags{ControlValue: SDFlagsOwnerDACL, Criticality: true}},
	)
	sr, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("LDAP ACL search: %w", err)
	}
	var out []ObjectACL
	for _, e := range sr.Entries {
		raw := e.GetRawAttributeValue("nTSecurityDescriptor")
		if len(raw) == 0 {
			continue
		}
		owner, findings, err := ParseSecurityDescriptor(raw)
		if err != nil {
			continue
		}
		if !includePrivileged {
			findings = FilterExpectedTrustees(findings)
		}
		if len(findings) == 0 {
			continue
		}
		out = append(out, ObjectACL{
			DN:       e.DN,
			SAM:      e.GetAttributeValue("sAMAccountName"),
			Category: objectCategory(e),
			OwnerSID: owner,
			Findings: findings,
		})
	}
	return out, nil
}

// ParseSecurityDescriptor reads a self-relative Windows SD and returns owner SID + interesting ACEs.
func ParseSecurityDescriptor(sd []byte) (owner string, findings []ACEFinding, err error) {
	if len(sd) < 20 {
		return "", nil, fmt.Errorf("sd too short (%d)", len(sd))
	}
	if sd[0] != 1 {
		return "", nil, fmt.Errorf("sd revision %d", sd[0])
	}
	ctrl := binary.LittleEndian.Uint16(sd[2:4])
	if ctrl&seSelfRelative == 0 {
		return "", nil, fmt.Errorf("sd not self-relative")
	}
	offOwner := binary.LittleEndian.Uint32(sd[4:8])
	if offOwner != 0 {
		if s, _, e := parseSID(sd, int(offOwner)); e == nil {
			owner = s
		}
	}
	if ctrl&seDACLPresent == 0 {
		return owner, nil, nil
	}
	offDACL := binary.LittleEndian.Uint32(sd[16:20])
	if offDACL == 0 || int(offDACL)+8 > len(sd) {
		return owner, nil, fmt.Errorf("dacl offset")
	}
	findings, err = parseDACL(sd, int(offDACL))
	return owner, findings, err
}

func parseDACL(sd []byte, off int) ([]ACEFinding, error) {
	aclSize := int(binary.LittleEndian.Uint16(sd[off+2 : off+4]))
	aceCount := int(binary.LittleEndian.Uint16(sd[off+4 : off+6]))
	if aclSize < 8 || off+aclSize > len(sd) {
		return nil, fmt.Errorf("acl size")
	}
	pos := off + 8
	end := off + aclSize
	var out []ACEFinding
	for i := 0; i < aceCount && pos+8 <= end; i++ {
		aceType := sd[pos]
		aceSize := int(binary.LittleEndian.Uint16(sd[pos+2 : pos+4]))
		if aceSize < 8 || pos+aceSize > end {
			break
		}
		if aceType == aceAllowed || aceType == aceAllowedObject {
			if f, ok := parseAllowedACE(sd[pos : pos+aceSize]); ok && len(f.Rights) > 0 {
				out = append(out, f)
			}
		}
		pos += aceSize
	}
	return out, nil
}

func parseAllowedACE(ace []byte) (ACEFinding, bool) {
	if len(ace) < 8+8 {
		return ACEFinding{}, false
	}
	mask := binary.LittleEndian.Uint32(ace[4:8])
	sidOff := 8
	var guid string
	if ace[0] == aceAllowedObject {
		if len(ace) < 12 {
			return ACEFinding{}, false
		}
		flags := binary.LittleEndian.Uint32(ace[8:12])
		sidOff = 12
		if flags&objectTypePresent != 0 {
			if sidOff+16 > len(ace) {
				return ACEFinding{}, false
			}
			guid = formatWindowsGUID(ace[sidOff : sidOff+16])
			sidOff += 16
		}
		if flags&0x00000002 != 0 { // inherited object type present
			sidOff += 16
		}
	}
	sid, _, err := parseSID(ace, sidOff)
	if err != nil {
		return ACEFinding{}, false
	}
	rights := ClassifyMask(mask, guid)
	if len(rights) == 0 {
		return ACEFinding{}, false
	}
	return ACEFinding{
		TrusteeSID: sid,
		Trustee:    WellKnownSIDName(sid),
		Rights:     rights,
		ObjectGUID: guid,
	}, true
}

// ClassifyMask maps an access mask (+ optional object-type GUID) to right names.
func ClassifyMask(mask uint32, objectGUID string) []string {
	g := strings.ToLower(strings.TrimSpace(objectGUID))
	var out []string
	if mask&RightGenericAll != 0 {
		out = append(out, "GenericAll")
	}
	if mask&RightGenericWrite != 0 {
		out = append(out, "GenericWrite")
	}
	if mask&RightWriteDACL != 0 {
		out = append(out, "WriteDacl")
	}
	if mask&RightWriteOwner != 0 {
		out = append(out, "WriteOwner")
	}
	if g == GUIDForceChangePassword && mask&RightControlAccess != 0 {
		out = append(out, "ForceChangePassword")
	}
	if g == GUIDAllowedToAct && mask&(RightWriteProperty|RightGenericWrite|RightGenericAll) != 0 {
		out = append(out, "AllowedToAct")
	}
	if g == "" && mask&RightWriteProperty != 0 && mask&RightGenericAll == 0 && mask&RightGenericWrite == 0 {
		out = append(out, "WriteProperty")
	}
	return out
}

// FilterExpectedTrustees drops BA/DA/EA/SYSTEM-style ACEs (default BloodHound-lite view).
func FilterExpectedTrustees(in []ACEFinding) []ACEFinding {
	var out []ACEFinding
	for _, f := range in {
		if IsExpectedPrivilegedSID(f.TrusteeSID) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// IsExpectedPrivilegedSID reports built-in / domain-admin class trustees.
func IsExpectedPrivilegedSID(sid string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549", "S-1-5-9", "S-1-5-32-551":
		return true
	}
	for _, rid := range []string{"-500", "-512", "-516", "-518", "-519", "-526", "-527"} {
		if strings.HasSuffix(sid, rid) {
			return true
		}
	}
	return false
}

// WellKnownSIDName maps a few SIDs operators recognize.
func WellKnownSIDName(sid string) string {
	switch sid {
	case "S-1-1-0":
		return "Everyone"
	case "S-1-5-11":
		return "Authenticated Users"
	case "S-1-5-18":
		return "SYSTEM"
	case "S-1-5-32-544":
		return "Administrators"
	case "S-1-5-32-545":
		return "Users"
	}
	if strings.HasSuffix(sid, "-512") {
		return "Domain Admins"
	}
	if strings.HasSuffix(sid, "-519") {
		return "Enterprise Admins"
	}
	if strings.HasSuffix(sid, "-500") {
		return "Administrator"
	}
	return ""
}

func parseSID(buf []byte, off int) (string, int, error) {
	if off < 0 || off+8 > len(buf) {
		return "", 0, fmt.Errorf("sid header")
	}
	rev := buf[off]
	nsub := int(buf[off+1])
	need := 8 + 4*nsub
	if nsub < 0 || nsub > 15 || off+need > len(buf) {
		return "", 0, fmt.Errorf("sid length")
	}
	var ia uint64
	for i := 0; i < 6; i++ {
		ia = (ia << 8) | uint64(buf[off+2+i])
	}
	var b strings.Builder
	fmt.Fprintf(&b, "S-%d-%d", rev, ia)
	for i := 0; i < nsub; i++ {
		fmt.Fprintf(&b, "-%d", binary.LittleEndian.Uint32(buf[off+8+4*i:]))
	}
	return b.String(), need, nil
}

func formatWindowsGUID(g []byte) string {
	if len(g) != 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(g[0:4])
	d2 := binary.LittleEndian.Uint16(g[4:6])
	d3 := binary.LittleEndian.Uint16(g[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%s-%s",
		d1, d2, d3, hex.EncodeToString(g[8:10]), hex.EncodeToString(g[10:16]))
}

func objectCategory(e *ldap.Entry) string {
	oc := strings.ToLower(e.GetAttributeValue("objectCategory"))
	if strings.Contains(oc, "computer") {
		return "computer"
	}
	if strings.Contains(oc, "group") {
		return "group"
	}
	for _, c := range e.GetAttributeValues("objectClass") {
		switch strings.ToLower(c) {
		case "computer":
			return "computer"
		case "group":
			return "group"
		}
	}
	return "user"
}
