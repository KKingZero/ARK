package ldapcli

import (
	"testing"
)

func TestPRPAttributeNames(t *testing.T) {
	if attrNeverReveal != "msDS-NeverRevealGroup" {
		t.Fatal(attrNeverReveal)
	}
	if attrRevealOnDemand != "msDS-RevealOnDemandGroup" {
		t.Fatal(attrRevealOnDemand)
	}
}

func TestPartialSecretsFlag(t *testing.T) {
	if uacPartialSecrets != 0x04000000 {
		t.Fatalf("0x%x", uacPartialSecrets)
	}
}
