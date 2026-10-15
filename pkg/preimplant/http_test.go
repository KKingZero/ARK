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

func TestHTTPRequiresURL(t *testing.T) {
	err := RunHTTP([]string{"get"})
	if err == nil {
		t.Fatal("expected usage")
	}
}

func TestHTTPUserRequiresPass(t *testing.T) {
	err := RunHTTP([]string{"get", "--url", "http://127.0.0.1/", "--user", "u"})
	if err == nil || !strings.Contains(err.Error(), "requires --pass") {
		t.Fatalf("got %v", err)
	}
}

func TestHTTPClientInsecureAndRedirectStripsAuth(t *testing.T) {
	cfg := httpClientConfig{Insecure: true, NTLM: false}
	c := newHTTPClient(cfg, nil)
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
	if err != nil || string(b) != "portal" {
		t.Fatalf("%q %v", b, err)
	}
}

func TestHTTPAnonymousGetPrintsHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("auth %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("X-Ark", "1")
		io.WriteString(w, "status-ok")
	}))
	defer ts.Close()
	res, err := httpFetch([]string{"--url", ts.URL + "/api/status"}, http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.body) != "status-ok" {
		t.Fatalf("body %q", res.body)
	}
	if res.header.Get("X-Ark") != "1" {
		t.Fatalf("headers %v", res.header)
	}
	var buf strings.Builder
	if err := writeHTTPResult(&buf, io.Discard, res); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "200 OK") || !strings.Contains(got, "X-Ark: 1") || !strings.HasSuffix(got, "status-ok") {
		t.Fatalf("printed %q", got)
	}
}

func TestHTTPPostFormAndCookieJar(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content-type %q", ct)
		}
		b, _ := io.ReadAll(r.Body)
		if string(b) != "password=serial" {
			t.Errorf("body %q", b)
		}
		if r.Header.Get("X-Lab") != "touch" {
			t.Errorf("header %q", r.Header.Get("X-Lab"))
		}
		http.SetCookie(w, &http.Cookie{Name: "nxsession", Value: "abc", Path: "/"})
		http.Redirect(w, r, "/dash", http.StatusFound)
	})
	mux.HandleFunc("/dash", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("nxsession")
		if err != nil || c.Value != "abc" {
			http.Error(w, "no cookie", http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "dashboard")
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()
	jar := t.TempDir() + "/cj"
	res, err := httpFetch([]string{
		"--url", ts.URL + "/login",
		"--data", "password=serial",
		"--header", "X-Lab: touch",
		"--cookie-jar", jar,
	}, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.body) != "dashboard" {
		t.Fatalf("body %q", res.body)
	}
	saved, err := os.ReadFile(jar)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), "nxsession=abc") {
		t.Fatalf("jar %q", saved)
	}
	info, err := os.Stat(jar)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v err %v", info, err)
	}

	res, err = httpFetch([]string{"--url", ts.URL + "/dash", "--cookie-jar", jar}, http.MethodGet)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.body) != "dashboard" {
		t.Fatalf("second body %q", res.body)
	}
}

func TestHTTPContentTypeFlag(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	_, err := httpFetch([]string{
		"--url", ts.URL,
		"--data", `{"a":1}`,
		"--content-type", "application/json",
	}, http.MethodPost)
	if err != nil {
		t.Fatal(err)
	}
	if got != "application/json" {
		t.Fatalf("content-type %q", got)
	}
}

func TestHTTPNTLMOnlyWithUser(t *testing.T) {
	off := newHTTPClient(httpClientConfig{}, nil)
	if _, ok := off.Transport.(*http.Transport); !ok {
		t.Fatalf("anonymous transport %T", off.Transport)
	}
	on := newHTTPClient(httpClientConfig{NTLM: true, User: "u", Pass: "p"}, nil)
	if _, ok := on.Transport.(*http.Transport); ok {
		t.Fatal("user transport skipped NTLM")
	}
}
