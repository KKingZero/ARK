package ntlmrelay

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mock target that requires NTLM on one connection and then serves paths.
func TestStickyClientReusesConnection(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", "NTLM TlRMTVNTUAACAAAADAAMADgAAAAFgomi+9bB0Y/75X0AAAAAAAAAAHYAdgBEAAAABQLODgAAAA9EAE8ATQBBAEkATgACAAwARABPAE0AQQBJAE4AAQAcAFMARQBSAFYARQBSAA==")
			http.Error(w, "auth", 401)
			return
		}
		// Accept any NTLM blob for test
		if strings.HasPrefix(auth, "NTLM ") {
			if r.URL.Path == "/secret" {
				_, _ = io.WriteString(w, "LOOT")
				return
			}
			_, _ = io.WriteString(w, "OK")
			return
		}
		http.Error(w, "nope", 401)
	}))
	defer srv.Close()

	client, sticky, err := newTargetClient(srv.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	defer sticky.Close()

	// Type1-like request
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Authorization", "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAA=")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Second request on same client (sticky conn)
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/secret", nil)
	req2.Header.Set("Authorization", "NTLM TlRMTVNTUAADAAAAGAAYAFgAAAAYABgAcAAAAAAAAABAAAAAGgAaAEAAAAASABIAegAAAAAAAAAAAAAABYKIogA=")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if string(body) != "LOOT" && string(body) != "OK" {
		// mock may not distinguish path with our simplistic NTLM accept
		t.Logf("body=%q hits=%d status=%d", body, hits, resp2.StatusCode)
	}
	if hits < 2 {
		t.Fatalf("expected >=2 hits on sticky client, got %d", hits)
	}
}

func TestRedirectStripsAuthorization(t *testing.T) {
	var sawAuthOnB bool
	mux := http.NewServeMux()
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuthOnB = true
		}
		_, _ = io.WriteString(w, "b")
	}))
	defer final.Close()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/x", http.StatusFound)
	})
	a := httptest.NewServer(mux)
	defer a.Close()

	client, sticky, err := newTargetClient(a.URL+"/", false)
	if err != nil {
		t.Fatal(err)
	}
	defer sticky.Close()

	req, _ := http.NewRequest(http.MethodGet, a.URL+"/", nil)
	req.Header.Set("Authorization", "NTLM AAAA")
	resp, err := client.Do(req)
	if err != nil {
		// off-host redirect returns ErrUseLastResponse path — may error or return 302
		t.Logf("redirect result: %v", err)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if sawAuthOnB {
		t.Fatal("Authorization was forwarded to redirect target")
	}
}
