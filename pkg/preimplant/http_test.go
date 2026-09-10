package preimplant

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRunHTTPHelp(t *testing.T) {
	if err := RunHTTP([]string{"help"}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRequiresURLUser(t *testing.T) {
	err := RunHTTP([]string{"get", "--url", "http://127.0.0.1/"})
	if err == nil {
		t.Fatal("expected usage")
	}
}

func TestHTTPClientInsecureAndRedirectStripsAuth(t *testing.T) {
	cfg := httpClientConfig{Insecure: true, NTLM: false}
	c := newHTTPClient(cfg)
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport %T", c.Transport)
	}
	if tr.TLSClientConfig == nil || !tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("insecure")
	}

	var sawAuth bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/next" {
			if r.Header.Get("Authorization") != "" {
				sawAuth = true
			}
			io.WriteString(w, "ok")
			return
		}
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic abc")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if string(b) != "ok" {
		t.Fatalf("body %q", b)
	}
	if sawAuth {
		t.Fatal("Authorization followed redirect")
	}
}

func TestHTTPGetWritesBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "portal")
	}))
	defer ts.Close()
	out := t.TempDir() + "/body.html"
	err := httpDo([]string{"--url", ts.URL, "--user", "u", "--pass", "p", "--no-ntlm", "--out", out}, http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), "portal") {
		t.Fatalf("%q %v", b, err)
	}
}
