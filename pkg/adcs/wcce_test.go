package adcs

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeICertRequestHasCSRAndTemplate(t *testing.T) {
	csr := []byte{0x30, 0x82, 0x01, 0x00, 0x00}
	b := encodeICertRequest(7, "danglingtree-CA", "CertificateTemplate:VPNUserTemplate\n", csr)
	if len(b) < 24 || b[2] != 0 {
		t.Fatalf("hdr %x", b[:8])
	}
	if binary.LittleEndian.Uint16(b[22:24]) != icertRequestDOpReq {
		t.Fatalf("opnum %d", binary.LittleEndian.Uint16(b[22:24]))
	}
	if !strings.Contains(string(b), "VPNUserTemplate") && !bytesContain(b, []byte{'V', 0, 'P', 0}) {
		// UTF-16 name
		if !utf16Contains(b, "VPNUserTemplate") {
			t.Fatal("missing template")
		}
	}
	if !bytesContain(b, csr) {
		t.Fatal("missing csr")
	}
}

func TestFindDERCert(t *testing.T) {
	n := 70
	cert := make([]byte, 4+n)
	cert[0], cert[1] = 0x30, 0x82
	cert[2], cert[3] = byte(n>>8), byte(n)
	got := findDERCert(append([]byte{0, 0, 0, 0}, cert...))
	if len(got) != len(cert) {
		t.Fatalf("%d", len(got))
	}
}

func TestParseICertRequestHRESULT(t *testing.T) {
	resp := make([]byte, 36)
	resp[2] = 2
	binary.LittleEndian.PutUint32(resp[24:28], 0x80070005)
	_, _, err := parseICertRequestResp(resp)
	if err == nil || !strings.Contains(err.Error(), "HRESULT") {
		t.Fatalf("%v", err)
	}
}

func utf16Contains(b []byte, s string) bool {
	for i := 0; i+1 < len(b); i++ {
		ok := true
		for j, r := range s {
			off := i + j*2
			if off+1 >= len(b) || b[off] != byte(r) || b[off+1] != 0 {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
