package scmr

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBindUUIDAndOpnum(t *testing.T) {
	b := dcerpcBind(1, scmrUUID, 2)
	if hex.EncodeToString(b[32:48]) != "81bb7a364498f135ad3298f038001003" {
		t.Fatalf("uuid %x", b[32:48])
	}
	if binary.LittleEndian.Uint16(b[48:50]) != 2 || b[2] != 11 {
		t.Fatalf("ver/ptype %d %d", binary.LittleEndian.Uint16(b[48:50]), b[2])
	}
	stub := encodeCreateServiceW(bytes20(), "Svc", `C:\Windows\Svc.exe`)
	req, err := dcerpcRequest(7, opCreateServiceW, stub)
	if err != nil {
		t.Fatal(err)
	}
	if req[2] != 0 || binary.LittleEndian.Uint16(req[22:24]) != opCreateServiceW {
		t.Fatalf("request ptype=%d op=%d", req[2], binary.LittleEndian.Uint16(req[22:24]))
	}
	if binary.LittleEndian.Uint16(req[8:10]) != uint16(len(req)) {
		t.Fatalf("frag %d want %d", binary.LittleEndian.Uint16(req[8:10]), len(req))
	}
}

func TestOpenSCManagerLayout(t *testing.T) {
	got := hex.EncodeToString(encodeOpenSCManagerW(`\\HOST`))
	// unique ptr, conformant \\HOST\0, null database, SC_MANAGER_ALL_ACCESS.
	want := "00000200" +
		"070000000000000007000000" +
		"5c005c0048004f00530054000000" +
		"0000" +
		"00000000" +
		"3f000f00"
	if got != want {
		t.Fatalf("open\n%s\n%s", got, want)
	}
}

func TestCreateAndStartLayout(t *testing.T) {
	h := bytes20()
	got := hex.EncodeToString(encodeCreateServiceW(h, "Svc", `C:\Windows\Svc.exe`))
	if !strings.Contains(got, utf16Hex("Svc")) {
		t.Fatalf("missing service name in %s", got)
	}
	if !strings.Contains(got, utf16Hex(`C:\Windows\Svc.exe`)) {
		t.Fatalf("missing binary path in %s", got)
	}
	want := hex.EncodeToString(h) +
		"040000000000000004000000" +
		"5300760063000000" +
		"00000000" +
		"ff010f00" +
		"10000000" +
		"03000000" +
		"00000000" +
		"130000000000000013000000" +
		"43003a005c00570069006e0064006f00770073005c005300760063002e006500780065000000" +
		"0000" +
		"00000000000000000000000000000000000000000000000000000000"
	if got != want {
		t.Fatalf("create\n%s\n%s", got, want)
	}
	start := encodeStartServiceW(h)
	req, err := dcerpcRequest(3, opStartServiceW, start)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint16(req[22:24]) != opStartServiceW {
		t.Fatalf("start op %d", binary.LittleEndian.Uint16(req[22:24]))
	}
	if hex.EncodeToString(start) != hex.EncodeToString(h)+"0000000000000000" {
		t.Fatalf("start %x", start)
	}
	if opCloseServiceHandle != 0 {
		t.Fatal(opCloseServiceHandle)
	}
}

func TestWin32ServiceExists(t *testing.T) {
	err := win32Err("CreateServiceW", 1073)
	if err == nil || !strings.Contains(err.Error(), "1073") {
		t.Fatal(err)
	}
}

func bytes20() []byte {
	b := make([]byte, 20)
	for i := range b {
		b[i] = 0x48
	}
	return b
}

func utf16Hex(s string) string {
	n := ndr{}
	n.wstr(s)
	return hex.EncodeToString(n.b)
}
