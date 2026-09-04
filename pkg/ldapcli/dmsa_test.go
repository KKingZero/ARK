package ldapcli

import (
	"strings"
	"testing"
)

func TestDMSAObjectClasses(t *testing.T) {
	if len(DMSAObjectClasses) < 6 {
		t.Fatalf("%v", DMSAObjectClasses)
	}
	joined := strings.Join(DMSAObjectClasses, ",")
	for _, want := range []string{"top", "person", "organizationalPerson", "user", "computer", "msDS-ManagedServiceAccount", "msDS-DelegatedManagedServiceAccount"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s in %v", want, DMSAObjectClasses)
		}
	}
}

func TestRemainingSupersedeLinks(t *testing.T) {
	got := remainingSupersedeLinks(
		[]string{"CN=pwn,OU=X,DC=a", "CN=other,OU=X,DC=a"},
		"CN=pwn,OU=X,DC=a",
	)
	if len(got) != 1 || got[0] != "CN=other,OU=X,DC=a" {
		t.Fatalf("%v", got)
	}
	got = remainingSupersedeLinks([]string{"CN=pwn,OU=X,DC=a"}, "cn=pwn,ou=x,dc=a")
	if len(got) != 0 {
		t.Fatalf("case fold: %v", got)
	}
}

func TestCreateDMSANilConn(t *testing.T) {
	if _, err := CreateDMSA(nil, "DC=a", "pwn", "OU=X,DC=a", "Administrator", "u", "a.htb"); err == nil {
		t.Fatal("nil conn")
	}
}

func TestDeleteDMSANilLookup(t *testing.T) {
	if err := DeleteDMSA(nil, "DC=a", "pwn$"); err == nil {
		t.Fatal("nil conn")
	}
}
