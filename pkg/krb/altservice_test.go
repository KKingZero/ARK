package krb

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestRewriteTicketSName(t *testing.T) {
	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "PIRATE.HTB",
		SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/WEB01.pirate.htb"),
		EncPart: types.EncryptedData{
			EType:  18,
			Cipher: []byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6},
		},
	}
	raw, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, pn, realm, err := RewriteTicketSName(raw, "CIFS/DC01.pirate.htb")
	if err != nil {
		t.Fatal(err)
	}
	if realm != "PIRATE.HTB" {
		t.Fatalf("realm %s", realm)
	}
	if strings.Join(pn.NameString, "/") != "CIFS/DC01.pirate.htb" {
		t.Fatalf("sname %+v", pn)
	}
	var got messages.Ticket
	if err := got.Unmarshal(out); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.SName.NameString, "/") != "CIFS/DC01.pirate.htb" {
		t.Fatalf("ticket sname %+v", got.SName)
	}
	if !bytes.Equal(got.EncPart.Cipher, tkt.EncPart.Cipher) {
		t.Fatal("enc-part changed")
	}
}

func TestRewriteTicketSNameRealm(t *testing.T) {
	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "PIRATE.HTB",
		SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/WEB01.pirate.htb"),
		EncPart: types.EncryptedData{
			EType:  18,
			Cipher: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	}
	raw, err := tkt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	_, _, realm, err := RewriteTicketSName(raw, "CIFS/DC01@OTHER.HTB")
	if err != nil {
		t.Fatal(err)
	}
	if realm != "OTHER.HTB" {
		t.Fatalf("realm %s", realm)
	}
}

func TestParseSPNWithRealmRejectsBare(t *testing.T) {
	if _, _, err := parseSPNWithRealm("CIFS"); err == nil {
		t.Fatal("bare")
	}
}
