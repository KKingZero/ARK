package krb

import (
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestGSSAuthenticatorUsesClockOffset(t *testing.T) {
	SetClockOffset(0)
	t.Cleanup(func() { SetClockOffset(0) })
	SetClockOffset(7 * time.Hour)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Administrator")
	auth, err := GSSAuthenticator("PIRATE.HTB", cname)
	if err != nil {
		t.Fatal(err)
	}
	delta := auth.CTime.Sub(time.Now().UTC())
	if delta < 6*time.Hour || delta > 8*time.Hour {
		t.Fatalf("CTime offset %v (want ~7h)", delta)
	}
	if auth.Cksum.CksumType != chksumtype.GSSAPI {
		t.Fatalf("cksum type %d", auth.Cksum.CksumType)
	}
	if len(auth.Cksum.Checksum) != 24 {
		t.Fatalf("cksum len %d", len(auth.Cksum.Checksum))
	}
}

func TestFindCachedTicket(t *testing.T) {
	tickets := []CachedTicket{
		{Server: []string{"cifs", "web01.pirate.htb"}, SRealm: "PIRATE.HTB"},
		{Server: []string{"krbtgt", "PIRATE.HTB"}, SRealm: "PIRATE.HTB"},
	}
	got, ok := FindCachedTicket(tickets, "cifs/WEB01.pirate.htb")
	if !ok {
		t.Fatal("miss")
	}
	if len(got.Server) != 2 {
		t.Fatalf("%v", got.Server)
	}
	if _, ok := FindCachedTicket(tickets, "ldap/dc01.pirate.htb"); ok {
		t.Fatal("ldap should miss")
	}
	tgt, ok := TGTFromCCache(tickets)
	if !ok || tgt.Server[0] != "krbtgt" {
		t.Fatal("tgt")
	}
}
