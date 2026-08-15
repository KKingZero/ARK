package smb

import (
	"testing"

	"github.com/KKingZero/erebus-exploit-framwork/pkg/smbcli"
)

func TestParseNTHash(t *testing.T) {
	nt := "603fc24ee01a9409f83c9d1d701485c5"
	b, err := smbcli.ParseNTHash(nt)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 32 {
		t.Fatalf("len=%d", len(b))
	}
	if b[0] != 0xaa || b[16] != 0x60 {
		t.Fatalf("unexpected bytes: %x", b)
	}
}

func TestNormalizeSharePath(t *testing.T) {
	if got := smbcli.NormalizePath(`\foo\bar`); got != "foo/bar" {
		t.Fatalf("got %q", got)
	}
	if got := smbcli.NormalizePath(""); got != "." {
		t.Fatalf("got %q", got)
	}
}
