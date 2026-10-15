package operatorcli

import (
	"os"
	"strings"
	"testing"
)

func TestReadUploadFileRejectsOverCap(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/big"
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxOpTransferBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := readUploadFile(path, "rel.bin"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("got %v", err)
	}
}

func TestReadUploadFileMarshalsRelative(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/note"
	if err := os.WriteFile(path, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	task, err := readUploadFile(path, "Desktop/note")
	if err != nil {
		t.Fatal(err)
	}
	if task.RemotePath != "Desktop/note" || string(task.Data) != "hi" {
		t.Fatalf("%+v", task)
	}
	b, err := marshalUpload(task)
	if err != nil || len(b) == 0 {
		t.Fatalf("marshal %d %v", len(b), err)
	}
	// Absolute remote paths are the implant's reject, not a second client policy.
	abs, err := readUploadFile(path, `C:\MySQL\lib\plugin\udf.dll`)
	if err != nil || abs.RemotePath == "" {
		t.Fatalf("abs %v %+v", err, abs)
	}
}

func TestParseDownloadArgs(t *testing.T) {
	remote, out, err := parseDownloadArgs([]string{"Desktop/user.txt", "--out", "user.txt"})
	if err != nil || remote != "Desktop/user.txt" || out != "user.txt" {
		t.Fatalf("%q %q %v", remote, out, err)
	}
	remote, out, err = parseDownloadArgs([]string{"--out", "user.txt", "Desktop/user.txt"})
	if err != nil || remote != "Desktop/user.txt" || out != "user.txt" {
		t.Fatalf("flipped %q %q %v", remote, out, err)
	}
	if _, _, err := parseDownloadArgs([]string{"Desktop/user.txt"}); err == nil {
		t.Fatal("missing --out")
	}
}

func TestSaveDownloadFileModeAndCap(t *testing.T) {
	path := t.TempDir() + "/user.txt"
	if err := saveDownloadFile(path, []byte("flag")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "flag" {
		t.Fatalf("%q %v", b, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", info, err)
	}
	big := make([]byte, maxOpTransferBytes+1)
	if err := saveDownloadFile(path+".big", big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(path + ".big"); !os.IsNotExist(err) {
		t.Fatal("over-cap file was written")
	}
}
