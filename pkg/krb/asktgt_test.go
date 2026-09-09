package krb

import (
	"encoding/hex"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/patype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestParseNTHash(t *testing.T) {
	b, err := parseNTHash("8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatalf("%x", b)
	}
	b, err = parseNTHash("aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil || hex.EncodeToString(b) != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatalf("%x %v", b, err)
	}
	if _, err := parseNTHash("zz"); err == nil {
		t.Fatal("short hash should fail")
	}
}

func TestAskTGTMutuallyExclusive(t *testing.T) {
	_, err := AskTGT(AskTGTOptions{Domain: "d.htb", Username: "u", Password: "p", Hash: "8846f7eaee8fb117ad06bdd830b7586c", KDC: "10.0.0.1"})
	if err == nil {
		t.Fatal("expected exclusive error")
	}
}

func TestAddPAEncTimestampKeyRC4(t *testing.T) {
	nt, _ := parseNTHash("8846f7eaee8fb117ad06bdd830b7586c")
	key := types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: nt}
	req := &messages.ASReq{}
	if err := addPAEncTimestampKey(req, key, messages.KRBError{}); err != nil {
		t.Fatal(err)
	}
	if len(req.PAData) == 0 || req.PAData[0].PADataType != patype.PA_ENC_TIMESTAMP {
		t.Fatalf("pa=%v", req.PAData)
	}
	if len(req.PAData[0].PADataValue) < 16 {
		t.Fatal("PA-ENC-TIMESTAMP too short")
	}
}
