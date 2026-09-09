package samr

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSanitizeComputer(t *testing.T) {
	got, err := sanitizeComputer("ATTACK")
	if err != nil || got != "ATTACK$" {
		t.Fatalf("got %q %v", got, err)
	}
	got, err = sanitizeComputer("ATTACK$")
	if err != nil || got != "ATTACK$" {
		t.Fatalf("got %q %v", got, err)
	}
}

func TestDomainNetBIOS(t *testing.T) {
	if domainNetBIOS("pirate.htb") != "PIRATE" {
		t.Fatal(domainNetBIOS("pirate.htb"))
	}
}

func TestEncodeConnect5(t *testing.T) {
	b := encodeConnect5("\\\\", accessMaxAllowed)
	if len(b) < 16 {
		t.Fatalf("short %d", len(b))
	}
	// InVersion = 1 is packed after access
	if binary.LittleEndian.Uint32(b[len(b)-16:len(b)-12]) != 1 {
		t.Fatalf("inversion %x", b[len(b)-16:])
	}
}

func TestDCERPCRequestOpnum(t *testing.T) {
	req, err := dcerpcRequest(2, opCreateUser2, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if req[2] != 0 {
		t.Fatalf("ptype %d", req[2])
	}
	op := binary.LittleEndian.Uint16(req[22:24])
	if op != opCreateUser2 {
		t.Fatalf("opnum %d", op)
	}
}

func TestDCERPCRequestRejectsHugeStub(t *testing.T) {
	_, err := dcerpcRequest(1, 1, make([]byte, maxFrag))
	if err == nil {
		t.Fatal("expected stub too large")
	}
}

func TestWorkstationFlag(t *testing.T) {
	if ufWorkstation != 0x1000 {
		t.Fatalf("UF_WORKSTATION_TRUST_ACCOUNT want 0x1000 got 0x%x", ufWorkstation)
	}
}

func TestParseSIDAndStatus(t *testing.T) {
	sid, err := encodeTestSID()
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 4+len(sid)+4)
	binary.LittleEndian.PutUint32(body[0:4], 0x20000)
	copy(body[4:], sid)
	binary.LittleEndian.PutUint32(body[4+len(sid):], 0)
	got, st := parseSIDAndStatus(body)
	if st != 0 {
		t.Fatalf("st=%d", st)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(sid) {
		t.Fatalf("got %x want %x", got, sid)
	}
}

func TestParseLookupRID(t *testing.T) {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], 1)
	binary.LittleEndian.PutUint32(body[4:8], 0x20000)
	binary.LittleEndian.PutUint32(body[8:12], 1)
	binary.LittleEndian.PutUint32(body[12:16], 500)
	binary.LittleEndian.PutUint32(body[16:20], 0)
	rid, st := parseLookupRID(body)
	if st != 0 || rid != 500 {
		t.Fatalf("rid=%d st=%d", rid, st)
	}
}

func encodeTestSID() ([]byte, error) {
	// S-1-5-21-1-2-3
	out := make([]byte, 8+16)
	out[0] = 1
	out[1] = 4
	out[7] = 5
	binary.LittleEndian.PutUint32(out[8:], 21)
	binary.LittleEndian.PutUint32(out[12:], 1)
	binary.LittleEndian.PutUint32(out[16:], 2)
	binary.LittleEndian.PutUint32(out[20:], 3)
	return out, nil
}

func TestBindUUID(t *testing.T) {
	b := dcerpcBind(1, samrUUID, samrVersion)
	if hex.EncodeToString(b[32:48]) != hex.EncodeToString(samrUUID) {
		t.Fatalf("uuid %x", b[32:48])
	}
	if !strings.HasPrefix(hex.EncodeToString(samrUUID), "78573412") {
		t.Fatal(hex.EncodeToString(samrUUID))
	}
}

func TestNTHashKnown(t *testing.T) {
	// MD4(UTF16LE("password")) = 8846f7eaee8fb117ad06bdd830b7586c
	got := hex.EncodeToString(ntHash("password"))
	if got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Fatalf("nt=%s", got)
	}
}

func TestCreateUser2ContainsSAM(t *testing.T) {
	n := ndr{}
	n.pad(20)
	n.rpcUnicodeString("ATTACK$")
	n.u32(ufWorkstation)
	u := utf16Hex("ATTACK$")
	if !strings.Contains(strings.ToLower(hex.EncodeToString(n.b)), u) {
		t.Fatalf("missing ATTACK$ in %x", n.b)
	}
}

func utf16Hex(s string) string {
	n := ndr{}
	n.rpcUnicodeString(s)
	return strings.ToLower(hex.EncodeToString(n.b))
}
