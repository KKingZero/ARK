package ldapcli

import (
	"fmt"
	"testing"
)

func TestCanonicalSetAttr(t *testing.T) {
	got, err := CanonicalSetAttr("scriptPath")
	if err != nil || got != "scriptPath" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := CanonicalSetAttr("description"); err == nil {
		t.Fatal("description must not be allowlisted")
	}
	got, err = CanonicalSetAttr("spn")
	if err != nil || got != "servicePrincipalName" {
		t.Fatalf("spn %s %v", got, err)
	}
	got, err = CanonicalSetAttr("servicePrincipalName")
	if err != nil || got != "servicePrincipalName" {
		t.Fatalf("spn attr %s %v", got, err)
	}
}

func TestSetAttrNilConn(t *testing.T) {
	if err := SetAttr(nil, "DC=a,DC=b", "u", "scriptPath", "x.bat"); err == nil {
		t.Fatal("nil conn")
	}
}

func TestSanitizeComputerName(t *testing.T) {
	got, err := SanitizeComputerName("ATTACK$")
	if err != nil || got != "ATTACK" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := SanitizeComputerName("thisnameistoolong"); err == nil {
		t.Fatal("len")
	}
	if _, err := SanitizeComputerName("bad name"); err == nil {
		t.Fatal("space")
	}
}

func TestRandomMachinePassword(t *testing.T) {
	p, err := RandomMachinePassword()
	if err != nil || len(p) < 16 {
		t.Fatal(err)
	}
	if ContainsSAMPrefix("ATTACK$", p) {
		t.Fatalf("password collided with SAM: %s", p)
	}
}

func TestAddComputerNilConn(t *testing.T) {
	if _, err := AddComputer(nil, "DC=a,DC=b", "X", "p"); err == nil {
		t.Fatal("nil")
	}
}

func TestIsWillNotPerform(t *testing.T) {
	if IsWillNotPerform(nil) {
		t.Fatal("nil")
	}
	if !IsWillNotPerform(fmt.Errorf("add computer: LDAP Result Code 53 \"Unwilling To Perform\": 00000057: SvcErr: DSID-031A1264, problem 5003 (WILL_NOT_PERFORM)")) {
		t.Fatal("want match")
	}
}
