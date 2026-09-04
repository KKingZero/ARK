package krb

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto/rfc4757"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestS4UByteArray(t *testing.T) {
	u := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"Administrator"}}
	got := s4uByteArray(u, "GARFIELD.HTB")
	// LE name-type 1 + name + realm + "Kerberos"
	want, _ := hex.DecodeString("01000000" + hex.EncodeToString([]byte("AdministratorGARFIELD.HTBKerberos")))
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("got %x want %x", got, want)
	}
}

func TestPAForUserChecksumMatchesRFC4757(t *testing.T) {
	u := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"Administrator"}}
	key := []byte("0123456789abcdef0123456789abcdef")
	data := s4uByteArray(u, "GARFIELD.HTB")
	pa, err := marshalPAForUser(u, "GARFIELD.HTB", types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: key})
	if err != nil {
		t.Fatal(err)
	}
	if pa.PADataType != 129 || len(pa.PADataValue) < 16 {
		t.Fatalf("pa %+v", pa)
	}
	sum, err := rfc4757.Checksum(key, keyusage.KERB_NON_KERB_CKSUM_SALT, data)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hex.EncodeToString(pa.PADataValue), hex.EncodeToString(sum)) {
		t.Fatalf("checksum not in PA-FOR-USER: pa=%x sum=%x", pa.PADataValue, sum)
	}
}

func TestValidateS4U(t *testing.T) {
	err := validateS4U(S4UOptions{})
	if err == nil {
		t.Fatal("empty")
	}
	err = validateS4U(S4UOptions{Domain: "x.htb", Username: "ATTACK$", KDC: "10.0.0.1", Password: "p"})
	if err == nil || !strings.Contains(err.Error(), "impersonate") {
		t.Fatalf("%v", err)
	}
	err = validateS4U(S4UOptions{Domain: "x.htb", Username: "ATTACK$", KDC: "10.0.0.1", Password: "p", Impersonate: "Administrator"})
	if err == nil || !strings.Contains(err.Error(), "spn") {
		t.Fatalf("%v", err)
	}
	if err := validateS4U(S4UOptions{
		Domain: "x.htb", Username: "ATTACK$", KDC: "10.0.0.1", Password: "p",
		Impersonate: "Administrator", SPN: "cifs/dc.x.htb",
	}); err != nil {
		t.Fatal(err)
	}
	if err := validateS4U(S4UOptions{
		Domain: "x.htb", Username: "ATTACKER", KDC: "10.0.0.1", Password: "p",
		Impersonate: "dmsa$", DMSA: true,
	}); err != nil {
		t.Fatal(err)
	}
	err = validateS4U(S4UOptions{
		Domain: "x.htb", Username: "ATTACK$", KDC: "10.0.0.1", Password: "p",
		Impersonate: "Administrator", SPN: "cifs/dc.x.htb", AltService: "noslash",
	})
	if err == nil || !strings.Contains(err.Error(), "altservice") {
		t.Fatalf("altservice: %v", err)
	}
}

func TestRequireAES(t *testing.T) {
	if err := requireAES(etypeID.AES256_CTS_HMAC_SHA1_96, "TGT"); err != nil {
		t.Fatal(err)
	}
	if err := requireAES(23, "TGT"); err == nil || !strings.Contains(err.Error(), "RC4") {
		t.Fatalf("%v", err)
	}
}

func TestParseSPN(t *testing.T) {
	pn, err := parseSPN("cifs/dc.garfield.htb@GARFIELD.HTB")
	if err != nil || pn.NameString[0] != "cifs" || pn.NameString[1] != "dc.garfield.htb" {
		t.Fatalf("%+v %v", pn, err)
	}
	if _, err := parseSPN("nopath"); err == nil {
		t.Fatal("bare")
	}
}

func TestSamOnly(t *testing.T) {
	if got := samOnly(`GARFIELD\ATTACK$`); got != "ATTACK$" {
		t.Fatal(got)
	}
	if got := samOnly("Administrator@garfield.htb"); got != "Administrator" {
		t.Fatal(got)
	}
}

func TestSendKDCRejectsEmpty(t *testing.T) {
	if _, err := SendKDC("", []byte{1}); err == nil {
		t.Fatal("empty kdc")
	}
	if _, err := SendKDC("127.0.0.1", nil); err == nil {
		t.Fatal("empty msg")
	}
}

func TestRequireImpersonated(t *testing.T) {
	pn := types.PrincipalName{NameString: []string{"Administrator"}}
	if err := requireImpersonated(pn, "Administrator"); err != nil {
		t.Fatal(err)
	}
	if err := requireImpersonated(pn, "ATTACK$"); err == nil {
		t.Fatal("want mismatch")
	}
}

func TestPickAESPreauth(t *testing.T) {
	if _, _, _, err := pickAESPreauth(nil); err == nil {
		t.Fatal("empty e-data")
	}
}

func TestTrimURI(t *testing.T) {
	if got := trimURI("LDAP://10.0.0.1"); got != "10.0.0.1" {
		t.Fatal(got)
	}
}

func TestMarshalPAPacOptionsRBCD(t *testing.T) {
	pa, err := marshalPAPacOptionsRBCD()
	if err != nil {
		t.Fatal(err)
	}
	if pa.PADataType != PA_PAC_OPTIONS {
		t.Fatalf("type %d", pa.PADataType)
	}
	if hex.EncodeToString(pa.PADataValue) != hex.EncodeToString(paPACOptionsRBCD) {
		t.Fatalf("got %x want %x", pa.PADataValue, paPACOptionsRBCD)
	}
}

func TestRestampKeepsPACOptions(t *testing.T) {
	pa, err := marshalPAPacOptionsRBCD()
	if err != nil {
		t.Fatal(err)
	}
	seq := types.PADataSequence{
		{PADataType: patype.PA_TGS_REQ, PADataValue: []byte{1}},
		pa,
	}
	kept := make(types.PADataSequence, 0, len(seq))
	for _, p := range seq {
		if p.PADataType != patype.PA_TGS_REQ {
			kept = append(kept, p)
		}
	}
	if len(kept) != 1 || kept[0].PADataType != PA_PAC_OPTIONS {
		t.Fatalf("%+v", kept)
	}
}
