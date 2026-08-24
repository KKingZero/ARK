package ldapcli

import (
	"strings"
	"testing"
)

func TestEncodeParseSIDRoundTrip(t *testing.T) {
	cases := []string{
		"S-1-5-21-1-2-3-1105",
		"S-1-5-32-544",
		"S-1-1-0",
		"S-1-5-18",
	}
	for _, c := range cases {
		b, err := EncodeSID(c)
		if err != nil {
			t.Fatalf("%s encode: %v", c, err)
		}
		got, err := ParseSID(b)
		if err != nil || got != c {
			t.Fatalf("%s parse: got %q err=%v", c, got, err)
		}
	}
	want := mustDecodeHex(t, "01050000000000051500000001000000020000000300000051040000")
	got, err := EncodeSID("S-1-5-21-1-2-3-1105")
	if err != nil || string(got) != string(want) {
		t.Fatalf("bytes %x err=%v", got, err)
	}
	if _, err := EncodeSID("not-a-sid"); err == nil {
		t.Fatal("garbage sid")
	}
	if _, err := EncodeSID("S-1-5"); err == nil {
		t.Fatal("short sid")
	}
}

func TestBuildAndListAllowedToAct(t *testing.T) {
	attack := "S-1-5-21-1-2-3-1105"
	other := "S-1-5-21-1-2-3-2105"
	sd, err := BuildAllowedToActSD(nil, []string{attack, other})
	if err != nil {
		t.Fatal(err)
	}
	sids, err := ListAllowedToAct(sd)
	if err != nil {
		t.Fatal(err)
	}
	if len(sids) != 2 || sids[0] != attack || sids[1] != other {
		t.Fatalf("%v", sids)
	}
	owner, findings, err := ParseSecurityDescriptor(sd)
	if err != nil {
		t.Fatal(err)
	}
	if owner != "S-1-5-32-544" {
		t.Fatalf("owner %s", owner)
	}
	if len(findings) == 0 {
		t.Fatal("expected allow ACEs")
	}
}

func TestListAllowedToActEmptyAndBad(t *testing.T) {
	sids, err := ListAllowedToAct(nil)
	if err != nil || len(sids) != 0 {
		t.Fatalf("%v %v", sids, err)
	}
	if _, err := ListAllowedToAct([]byte{1, 2, 3}); err == nil {
		t.Fatal("short")
	}
}

func TestWriteRBCDNilConn(t *testing.T) {
	if _, err := WriteRBCD(nil, "DC=a,DC=b", "DC$", "ATTACK$"); err == nil {
		t.Fatal("nil conn")
	}
	if _, err := ClearRBCD(nil, "DC=a,DC=b", "DC$", ""); err == nil {
		t.Fatal("nil conn clear")
	}
	if _, err := ReadRBCD(nil, "DC=a,DC=b", "DC$"); err == nil {
		t.Fatal("nil conn read")
	}
}

func TestBuildAllowedToActKeepsOwner(t *testing.T) {
	owner, err := EncodeSID("S-1-5-21-1-2-3-500")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := BuildAllowedToActSD(owner, []string{"S-1-5-21-1-2-3-1105"})
	if err != nil {
		t.Fatal(err)
	}
	gotOwner, _, err := ParseSecurityDescriptor(sd)
	if err != nil || gotOwner != "S-1-5-21-1-2-3-500" {
		t.Fatalf("owner %s err=%v", gotOwner, err)
	}
}

func TestContainsSID(t *testing.T) {
	if !containsSID([]string{"S-1-5-18"}, "s-1-5-18") {
		t.Fatal("case")
	}
	if containsSID([]string{"S-1-5-18"}, "S-1-5-19") {
		t.Fatal("mismatch")
	}
}

func TestBuildAllowedToActRejectsBadTrustee(t *testing.T) {
	if _, err := BuildAllowedToActSD(nil, []string{"nope"}); err == nil || !strings.Contains(err.Error(), "sid") {
		t.Fatalf("%v", err)
	}
}

func TestListAllowedToActKeepsUnclassifiedMask(t *testing.T) {
	sid := mustDecodeHex(t, "01050000000000051500000001000000020000000300000051040000")
	other, err := EncodeSID("S-1-5-21-1-2-3-2105")
	if err != nil {
		t.Fatal(err)
	}
	aces := [][]byte{
		allowedACE(0, RightGenericAll, sid),
		allowedACE(0, RightControlAccess, other), // ClassifyMask would drop this
	}
	sd := buildSelfRelativeSD(t, sid, aces)
	sids, err := ListAllowedToAct(sd)
	if err != nil {
		t.Fatal(err)
	}
	if len(sids) != 2 || sids[0] != "S-1-5-21-1-2-3-1105" || sids[1] != "S-1-5-21-1-2-3-2105" {
		t.Fatalf("%v", sids)
	}
}

func TestRejectDeniedAllowedToAct(t *testing.T) {
	sid := mustDecodeHex(t, "01050000000000051500000001000000020000000300000051040000")
	deny := allowedACE(0, RightGenericAll, sid)
	deny[0] = aceDenied
	sd := buildSelfRelativeSD(t, sid, [][]byte{deny})
	if err := rejectDeniedAllowedToAct(sd); err == nil {
		t.Fatal("want deny refuse")
	}
	okSD := buildSelfRelativeSD(t, sid, [][]byte{allowedACE(0, RightGenericAll, sid)})
	if err := rejectDeniedAllowedToAct(okSD); err != nil {
		t.Fatal(err)
	}
}

func TestSamCandidates(t *testing.T) {
	got := samCandidates("ATTACK")
	if len(got) != 2 || got[0] != "ATTACK$" || got[1] != "ATTACK" {
		t.Fatalf("%v", got)
	}
	got = samCandidates("ATTACK$")
	if len(got) != 1 || got[0] != "ATTACK$" {
		t.Fatalf("%v", got)
	}
}
