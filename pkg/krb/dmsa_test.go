package krb

import (
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestParseDMSAKeyPackage(t *testing.T) {
	p := dmsaPkgASN{
		Current: []dmsaKeyASN{{KeyType: 18, KeyValue: []byte{1, 2, 3, 4}}},
		Previous: []dmsaKeyASN{
			{KeyType: 23, KeyValue: []byte{0x3a, 0x50, 0x26, 0xb2, 0xaa, 0x5e, 0xf2, 0xcb, 0xb7, 0xcb, 0x6a, 0x7b, 0xe3, 0xa2, 0xbc, 0xfa}},
		},
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDMSAKeyPackage(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Current) != 1 || got.Current[0].TypeName() != "AES256" {
		t.Fatalf("%+v", got.Current)
	}
	if len(got.Previous) != 1 || got.Previous[0].TypeName() != "RC4" {
		t.Fatalf("%+v", got.Previous)
	}
	if got.Previous[0].Hex() != "3a5026b2aa5ef2cbb7cb6a7be3a2bcfa" {
		t.Fatalf("hex %s", got.Previous[0].Hex())
	}
}

func TestParseDMSAKeyPackageEmpty(t *testing.T) {
	if _, err := ParseDMSAKeyPackage(nil); err == nil {
		t.Fatal("empty")
	}
}

func TestDMSAKeyPackageDump(t *testing.T) {
	p := DMSAKeyPackage{
		Current:  []DMSAKey{{KeyType: 18, KeyValue: []byte{1}}},
		Previous: []DMSAKey{{KeyType: 23, KeyValue: []byte{0xaa}}},
	}
	s := p.Dump()
	if !strings.Contains(s, "AES256:01") || !strings.Contains(s, "RC4:aa") {
		t.Fatal(s)
	}
}

func TestMarshalPAS4UX509User(t *testing.T) {
	u := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"dmsa$"}}
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	pa, err := marshalPAS4UX509UserNonce(u, "ODYSSEY.HTB", key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pa.PADataType != patype.PA_FOR_X509_USER {
		t.Fatalf("type %d want %d", pa.PADataType, patype.PA_FOR_X509_USER)
	}
	if len(pa.PADataValue) < 16 {
		t.Fatalf("short pa %d", len(pa.PADataValue))
	}
	again, err := marshalPAS4UX509UserNonce(u, "ODYSSEY.HTB", key, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(pa.PADataValue) != string(again.PADataValue) {
		t.Fatal("checksum not deterministic for fixed nonce")
	}
}

func TestDMSAKeysFromTGS(t *testing.T) {
	p := dmsaPkgASN{
		Current:  []dmsaKeyASN{{KeyType: 18, KeyValue: []byte{1, 2}}},
		Previous: []dmsaKeyASN{{KeyType: 23, KeyValue: []byte{0xde, 0xad}}},
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var rep messages.TGSRep
	if _, err := dmsaKeysFromTGS(rep); err == nil {
		t.Fatal("empty enc-pa")
	}
	rep.DecryptedEncPart.EncPAData = types.PADataSequence{{
		PADataType: PA_DMSA_KEY_PACKAGE, PADataValue: b,
	}}
	got, err := dmsaKeysFromTGS(rep)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Previous) != 1 || got.Previous[0].Hex() != "dead" {
		t.Fatalf("%+v", got)
	}
	rep.DecryptedEncPart.EncPAData[0].PADataValue, _ = asn1.Marshal(dmsaPkgASN{
		Current: []dmsaKeyASN{{KeyType: 18, KeyValue: []byte{1}}},
	})
	if _, err := dmsaKeysFromTGS(rep); err == nil || !strings.Contains(err.Error(), "previous-keys") {
		t.Fatalf("want previous-keys fail: %v", err)
	}
}
