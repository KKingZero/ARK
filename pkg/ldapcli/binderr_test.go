package ldapcli

import (
	"fmt"
	"testing"
)

func TestClassifyBindError(t *testing.T) {
	if ClassifyBindError(nil) != "success" {
		t.Fatal("nil")
	}
	if got := ClassifyBindError(fmt.Errorf("LDAP Result Code 49 \"Invalid Credentials\": 80090308: LdapErr: DSID-0C09044A, comment: AcceptSecurityContext error, data 533, v4563")); got != "disabled(533)" {
		t.Fatalf("disabled got %s", got)
	}
	if got := ClassifyBindError(fmt.Errorf("LDAP bind: data 775")); got != "locked" {
		t.Fatalf("locked got %s", got)
	}
	if got := ClassifyBindError(fmt.Errorf("LDAP bind: Invalid Credentials data 52e")); got != "invalid" {
		t.Fatalf("invalid got %s", got)
	}
}
