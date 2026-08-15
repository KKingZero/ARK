package ntlmrelay

import (
	"strings"
	"testing"
)

func TestDoubleEncodePathGhostlinkVectors(t *testing.T) {
	// Python: urllib.parse.quote(urllib.parse.quote(path, safe=""), safe="")
	cases := []struct {
		path        string
		want        string // golden: double percentEncodeAll
		mustContain []string
	}{
		{
			path:        `..\windows\win.ini`,
			mustContain: []string{"%252e%252e", "%255c", "win", "ini"},
		},
		{
			path:        `..\..\..\users\svc_canary\ntuser.dat`,
			mustContain: []string{"%252e", "%255c", "svc", "ntuser"},
		},
		{
			path:        `\\127.0.0.1\C$\Windows\win.ini`,
			mustContain: []string{"%255c", "127", "Windows", "win"},
		},
	}
	for _, tc := range cases {
		enc := DoubleEncodePath(tc.path)
		// Self-consistency: double percentEncodeAll
		want := percentEncodeAll(percentEncodeAll(tc.path))
		if enc != want {
			t.Errorf("path %q:\n  got  %q\n  want %q", tc.path, enc, want)
		}
		// Single encode must encode dots and backslashes
		once := percentEncodeAll(tc.path)
		if !strings.Contains(once, "%2E") && strings.Contains(tc.path, ".") {
			t.Errorf("single encode should encode dots: %q → %q", tc.path, once)
		}
		if strings.Contains(tc.path, `\`) && !strings.Contains(once, "%5C") {
			t.Errorf("single encode should encode backslash: %q → %q", tc.path, once)
		}
		for _, sub := range tc.mustContain {
			if !strings.Contains(enc, sub) && !strings.Contains(strings.ToLower(enc), strings.ToLower(sub)) {
				// alphanumeric parts stay literal
				if strings.ContainsAny(sub, "%") {
					t.Errorf("path %q: encode %q missing %q", tc.path, enc, sub)
				} else if !strings.Contains(enc, sub) {
					t.Errorf("path %q: encode %q missing literal %q", tc.path, enc, sub)
				}
			}
		}
	}
}

func TestJoinDownloadAPI(t *testing.T) {
	u := JoinDownloadAPI("/api/download", `..\win.ini`, true)
	if !strings.HasPrefix(u, "/api/download/") {
		t.Fatalf("got %q", u)
	}
	if strings.Contains(u, `..\`) {
		t.Fatalf("raw path leaked: %q", u)
	}
	// double-encoded dots (%252E or %252e)
	if !strings.Contains(strings.ToUpper(u), "%252E") {
		t.Fatalf("expected double-encoded dots in %q", u)
	}
}

func TestParseType3IdentityMinimal(t *testing.T) {
	if _, _, err := ParseType3Identity([]byte("short")); err == nil {
		t.Fatal("expected error")
	}
}

func TestCheckListenPort(t *testing.T) {
	if err := CheckListenPort("127.0.0.1:8888", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckListenPort("0.0.0.0:80", false); err == nil {
		t.Fatal("expected priv port error")
	}
	if err := CheckListenPort(":445", true); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAPIAddr(t *testing.T) {
	if err := CheckAPIAddr("127.0.0.1:18765", false); err != nil {
		t.Fatal(err)
	}
	if err := CheckAPIAddr("0.0.0.0:18765", false); err == nil {
		t.Fatal("expected non-loopback reject")
	}
	if err := CheckAPIAddr("0.0.0.0:18765", true); err != nil {
		t.Fatal(err)
	}
}
