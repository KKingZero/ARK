package ldapcli

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseSIDAndWellKnown(t *testing.T) {
	// S-1-5-21-1-2-3-1105
	sid := mustDecodeHex(t, "01050000000000051500000001000000020000000300000051040000")
	got, n, err := parseSID(sid, 0)
	if err != nil || n != len(sid) || got != "S-1-5-21-1-2-3-1105" {
		t.Fatalf("got %q n=%d err=%v", got, n, err)
	}
	if WellKnownSIDName("S-1-1-0") != "Everyone" {
		t.Fatal("everyone")
	}
	if !IsExpectedPrivilegedSID("S-1-5-32-544") || !IsExpectedPrivilegedSID("S-1-5-21-9-9-9-512") {
		t.Fatal("privileged")
	}
	if IsExpectedPrivilegedSID("S-1-5-21-1-2-3-1105") {
		t.Fatal("support user must not be filtered")
	}
}

func TestClassifyMask(t *testing.T) {
	if got := ClassifyMask(RightGenericAll, ""); !containsRight(got, "GenericAll") {
		t.Fatalf("%v", got)
	}
	if got := ClassifyMask(RightControlAccess, GUIDForceChangePassword); !containsRight(got, "ForceChangePassword") {
		t.Fatalf("%v", got)
	}
	if got := ClassifyMask(RightWriteProperty, GUIDAllowedToAct); !containsRight(got, "AllowedToAct") {
		t.Fatalf("%v", got)
	}
	if got := ClassifyMask(RightWriteProperty, GUIDKeyCredentialLink); !containsRight(got, "AddKeyCredentialLink") {
		t.Fatalf("%v", got)
	}
	if got := ClassifyMask(RightControlAccess, ""); len(got) != 0 {
		t.Fatalf("control access without GUID should not classify: %v", got)
	}
}

func TestParseSecurityDescriptor_GenericAllAndFCP(t *testing.T) {
	support := mustDecodeHex(t, "01050000000000051500000001000000020000000300000051040000")
	da := mustDecodeHex(t, "01050000000000051500000001000000020000000300000000020000") // RID 512
	fcpGUID := windowsGUID(t, GUIDForceChangePassword)

	aces := [][]byte{
		allowedACE(0, RightGenericAll, support),
		allowedObjectACE(RightControlAccess, fcpGUID, support),
		allowedACE(0, RightGenericAll, da),
	}
	sd := buildSelfRelativeSD(t, support, aces)

	owner, findings, err := ParseSecurityDescriptor(sd)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "S-1-5-21-1-2-3-1105" {
		t.Fatalf("owner %s", owner)
	}
	if len(findings) != 3 {
		t.Fatalf("findings %d: %+v", len(findings), findings)
	}
	filtered := FilterExpectedTrustees(findings)
	if len(filtered) != 2 {
		t.Fatalf("filtered %d: %+v", len(filtered), filtered)
	}
	var sawGA, sawFCP bool
	for _, f := range filtered {
		if f.TrusteeSID != "S-1-5-21-1-2-3-1105" {
			t.Fatalf("trustee %s", f.TrusteeSID)
		}
		if containsRight(f.Rights, "GenericAll") {
			sawGA = true
		}
		if containsRight(f.Rights, "ForceChangePassword") {
			sawFCP = true
			if f.ObjectGUID != GUIDForceChangePassword {
				t.Fatalf("guid %s", f.ObjectGUID)
			}
		}
	}
	if !sawGA || !sawFCP {
		t.Fatalf("missing rights: %+v", filtered)
	}
}

func TestParseSecurityDescriptor_Errors(t *testing.T) {
	if _, _, err := ParseSecurityDescriptor([]byte{1, 2, 3}); err == nil {
		t.Fatal("short")
	}
	if _, _, err := ParseSecurityDescriptor(make([]byte, 20)); err == nil {
		t.Fatal("not self-relative")
	}
}

func TestSearchACLNilConn(t *testing.T) {
	if _, err := SearchACL(nil, "DC=a,DC=b", false); err == nil {
		t.Fatal("nil conn")
	}
}

func TestACLSearchFilter(t *testing.T) {
	got := ACLSearchFilter("")
	if !strings.Contains(got, "objectCategory=person") {
		t.Fatalf("full walk filter: %s", got)
	}
	got = ACLSearchFilter("m.carter")
	if got != "(sAMAccountName=m.carter)" {
		t.Fatalf("sam filter: %s", got)
	}
	if strings.Contains(got, "objectCategory=person") {
		t.Fatal("sam filter must not walk the forest")
	}
}

func TestFilterDefaultACEs(t *testing.T) {
	in := []ACEFinding{
		{TrusteeSID: "S-1-5-11", Trustee: "Authenticated Users", Rights: []string{"WriteProperty"}},
		{TrusteeSID: "S-1-5-11", Trustee: "Authenticated Users", Rights: []string{"GenericAll"}},
		{TrusteeSID: "S-1-5-21-1-2-3-1105", Rights: []string{"WriteProperty"}},
	}
	got := FilterDefaultACEs(in)
	if len(got) != 2 {
		t.Fatalf("len %d: %+v", len(got), got)
	}
	if got[0].Rights[0] != "GenericAll" {
		t.Fatalf("kept wrong ACE: %+v", got[0])
	}
}

func containsRight(rs []string, want string) bool {
	for _, r := range rs {
		if r == want {
			return true
		}
	}
	return false
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func windowsGUID(t *testing.T, s string) []byte {
	t.Helper()
	p := strings.Split(s, "-")
	if len(p) != 5 {
		t.Fatal(s)
	}
	d1, err := hex.DecodeString(p[0])
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := hex.DecodeString(p[1])
	d3, _ := hex.DecodeString(p[2])
	d4a, _ := hex.DecodeString(p[3])
	d4b, _ := hex.DecodeString(p[4])
	out := make([]byte, 16)
	// Windows GUID: Data1/2/3 little-endian
	out[0], out[1], out[2], out[3] = d1[3], d1[2], d1[1], d1[0]
	out[4], out[5] = d2[1], d2[0]
	out[6], out[7] = d3[1], d3[0]
	copy(out[8:10], d4a)
	copy(out[10:], d4b)
	return out
}

func allowedACE(flags byte, mask uint32, sid []byte) []byte {
	ace := make([]byte, 8+len(sid))
	ace[0] = aceAllowed
	ace[1] = flags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

func allowedObjectACE(mask uint32, guid, sid []byte) []byte {
	ace := make([]byte, 12+16+len(sid))
	ace[0] = aceAllowedObject
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], mask)
	binary.LittleEndian.PutUint32(ace[8:12], objectTypePresent)
	copy(ace[12:28], guid)
	copy(ace[28:], sid)
	return ace
}

func buildSelfRelativeSD(t *testing.T, owner []byte, aces [][]byte) []byte {
	t.Helper()
	const hdr = 20
	aclBody := 8
	for _, a := range aces {
		aclBody += len(a)
	}
	offDACL := hdr
	offOwner := hdr + aclBody
	sd := make([]byte, offOwner+len(owner))
	sd[0] = 1
	binary.LittleEndian.PutUint16(sd[2:4], seSelfRelative|seDACLPresent)
	binary.LittleEndian.PutUint32(sd[4:8], uint32(offOwner))
	binary.LittleEndian.PutUint32(sd[16:20], uint32(offDACL))
	sd[offDACL] = 4 // ACL revision (object ACEs)
	binary.LittleEndian.PutUint16(sd[offDACL+2:offDACL+4], uint16(aclBody))
	binary.LittleEndian.PutUint16(sd[offDACL+4:offDACL+6], uint16(len(aces)))
	p := offDACL + 8
	for _, a := range aces {
		copy(sd[p:], a)
		p += len(a)
	}
	copy(sd[offOwner:], owner)
	return sd
}
