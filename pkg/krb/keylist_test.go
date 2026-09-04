package krb

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestRODCKvno(t *testing.T) {
	if got := RODCKvno(8245); got != 8245<<16 {
		t.Fatalf("%d", got)
	}
}

func TestValidateKeyList(t *testing.T) {
	_, err := ValidateKeyList(KeyListOptions{})
	if err == nil {
		t.Fatal("empty")
	}
	_, err = ValidateKeyList(KeyListOptions{
		RODCNumber: 8245, User: "Administrator", Domain: "x.htb", KDC: "10.0.0.1",
		AESKeyHex: "deadbeef",
	})
	if err == nil {
		t.Fatal("short key")
	}
	_, err = ValidateKeyList(KeyListOptions{
		RODCNumber: 8245, User: "Administrator", Domain: "x.htb", KDC: "10.0.0.1",
		AESKeyHex: strings.Repeat("ab", 16), // 32 hex = RC4-sized
	})
	if err == nil || !strings.Contains(err.Error(), "AES256") {
		t.Fatalf("rc4-sized key: %v", err)
	}
	kv, err := ValidateKeyList(KeyListOptions{
		RODCNumber: 8245, User: "Administrator", Domain: "x.htb", KDC: "10.0.0.1",
		AESKeyHex: "d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240",
	})
	if err != nil || kv != 8245<<16 {
		t.Fatalf("%d %v", kv, err)
	}
	if _, err := ValidateKeyList(KeyListOptions{Ticket: "abc"}); err != nil {
		t.Fatal(err)
	}
}

func TestKeyListReqRepRoundTrip(t *testing.T) {
	b, err := MarshalKeyListReq([]int32{etypeID.RC4_HMAC})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 || b[0] != 0x30 {
		t.Fatalf("want SEQUENCE, got %x", b)
	}
	nt := make([]byte, 16)
	for i := range nt {
		nt[i] = byte(i + 1)
	}
	rep, err := marshalKeyListRep([]types.EncryptionKey{{
		KeyType:  etypeID.RC4_HMAC,
		KeyValue: nt,
	}})
	if err != nil {
		t.Fatal(err)
	}
	keys, err := UnmarshalKeyListRep(rep)
	if err != nil {
		t.Fatal(err)
	}
	got, et, err := ntHashFromKeys(keys)
	if err != nil || et != etypeID.RC4_HMAC {
		t.Fatalf("%s %d %v", got, et, err)
	}
	if got != hex.EncodeToString(nt) {
		t.Fatalf("%s", got)
	}
}

func TestForgeRODCTGTRoundTrip(t *testing.T) {
	aes := "d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240"
	raw, _ := hex.DecodeString(aes)
	opts := KeyListOptions{
		RODCNumber: 8245,
		AESKeyHex:  aes,
		User:       "Administrator",
		Domain:     "garfield.htb",
		KDC:        "10.0.0.1",
	}
	tkt, skey, cname, err := ForgeRODCTGT(opts)
	if err != nil {
		t.Fatal(err)
	}
	if tkt.EncPart.KVNO != int(RODCKvno(8245)) {
		t.Fatalf("kvno %d", tkt.EncPart.KVNO)
	}
	if tkt.EncPart.EType != etypeID.AES256_CTS_HMAC_SHA1_96 {
		t.Fatalf("etype %d", tkt.EncPart.EType)
	}
	if skey.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 || len(skey.KeyValue) != 32 {
		t.Fatalf("session %+v", skey)
	}
	plain, err := crypto.DecryptEncPart(tkt.EncPart, types.EncryptionKey{
		KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: raw,
	}, uint32(keyusage.KDC_REP_TICKET))
	if err != nil {
		t.Fatal(err)
	}
	var etp messages.EncTicketPart
	if err := etp.Unmarshal(plain); err != nil {
		t.Fatal(err)
	}
	if len(etp.CName.NameString) == 0 || etp.CName.NameString[0] != "Administrator" {
		t.Fatalf("cname %+v (want %v)", etp.CName, cname)
	}
	if etp.CRealm != "GARFIELD.HTB" {
		t.Fatalf("crealm %s", etp.CRealm)
	}
}

func TestKeyListTGSMissingDC(t *testing.T) {
	_, err := KeyList(KeyListOptions{Ticket: "nope"})
	if err == nil {
		t.Fatal("want error")
	}
}
