package ldapcli

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestBaseDN(t *testing.T) {
	if got := BaseDN("danglingtree.htb"); got != "DC=danglingtree,DC=htb" {
		t.Fatalf("got %q", got)
	}
	if BaseDN("") != "" {
		t.Fatal("empty")
	}
	if BaseDN("foo)(cn=*") != "" {
		t.Fatal("injection domain must be rejected")
	}
}

func TestSplitUser(t *testing.T) {
	d, u := SplitUser(`DANGLINGTREE\jake.h`, "danglingtree.htb")
	if d != "DANGLINGTREE" || u != "jake.h" {
		t.Fatalf("%s %s", d, u)
	}
	d, u = SplitUser("jake.h@danglingtree.htb", "")
	if d != "danglingtree.htb" || u != "jake.h" {
		t.Fatalf("%s %s", d, u)
	}
	d, u = SplitUser("jake.h", "danglingtree.htb")
	if d != "danglingtree" || u != "jake.h" {
		t.Fatalf("netbios %s %s", d, u)
	}
}

func TestNormalizeHash(t *testing.T) {
	nt := "8cacb3a97e460c65d105ca7cd9913925"
	if got := NormalizeHash("aad3b435b51404eeaad3b435b51404ee:" + nt); got != nt {
		t.Fatalf("got %s", got)
	}
	if got := NormalizeHash("AAD3B435B51404EEAAD3B435B51404EE" + nt); got != nt {
		t.Fatalf("64hex got %s", got)
	}
}

func TestContainsSAMPrefix(t *testing.T) {
	if !ContainsSAMPrefix("jake.h", "JakeReset#2026!") {
		t.Fatal("expected jake prefix hit")
	}
	if ContainsSAMPrefix("jake.h", "Aa1!Aa1!Aa1!Aa1!") {
		t.Fatal("unique password should pass")
	}
	if !ContainsSAMPrefix("anderson.w", "AndersonSecret1!") {
		t.Fatal("expected anderson prefix")
	}
}

func TestSetPasswordRejectsQuote(t *testing.T) {
	err := SetPassword(nil, "DC=a,DC=b", "jake.h", `x"y`, false)
	if err == nil || !strings.Contains(err.Error(), "double-quote") {
		t.Fatalf("got %v", err)
	}
}

func TestEncodeUnicodePwd(t *testing.T) {
	b := EncodeUnicodePwd("x")
	want := utf16.Encode([]rune(`"x"`))
	if len(b) != len(want)*2 {
		t.Fatalf("len %d", len(b))
	}
	for i, r := range want {
		if binary.LittleEndian.Uint16(b[i*2:]) != r {
			t.Fatalf("u16[%d]", i)
		}
	}
}

func TestFilterFor(t *testing.T) {
	f, err := FilterFor("interesting", "DC=a,DC=b")
	if err != nil || f == "" {
		t.Fatal(err)
	}
	f2, err := FilterFor("domain_admins", "DC=a,DC=b")
	if err != nil || f2 == "" {
		t.Fatal(err)
	}
	if _, err := FilterFor("nope", ""); err == nil {
		t.Fatal("want error")
	}
}

func TestCanonicalQueryAliases(t *testing.T) {
	if CanonicalQuery("asrep") != "asrep_roastable" {
		t.Fatal(CanonicalQuery("asrep"))
	}
	if CanonicalQuery("keycred") != "shadow" {
		t.Fatal(CanonicalQuery("keycred"))
	}
	f, err := FilterFor("spn", "")
	if err != nil || !strings.Contains(f, "servicePrincipalName") {
		t.Fatalf("spn alias: %s %v", f, err)
	}
	f, err = FilterFor("shadow", "")
	if err != nil || !strings.Contains(f, "KeyCredentialLink") {
		t.Fatalf("shadow: %s %v", f, err)
	}
	if _, err := FilterFor("maq", "DC=a,DC=b"); err == nil {
		t.Fatal("maq is not a subtree filter")
	}
	if _, err := FilterFor("acl", "DC=a,DC=b"); err == nil {
		t.Fatal("acl is host-only")
	}
}

func TestAvailableTypesSorted(t *testing.T) {
	got := AvailableTypes()
	if len(got) < 10 {
		t.Fatalf("too few: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Fatalf("unsorted: %q then %q", got[i-1], got[i])
		}
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "shadow") || !strings.Contains(joined, "maq") || !strings.Contains(joined, "acl") {
		t.Fatal(joined)
	}
}

func TestParseMAQ(t *testing.T) {
	n, err := ParseMAQ("10")
	if err != nil || n != 10 {
		t.Fatalf("%d %v", n, err)
	}
	if _, err := ParseMAQ("x"); err == nil {
		t.Fatal("want error")
	}
	_, ok, err := ReadMAQ(nil, "DC=a,DC=b")
	if err == nil || ok {
		t.Fatal("nil conn")
	}
}
