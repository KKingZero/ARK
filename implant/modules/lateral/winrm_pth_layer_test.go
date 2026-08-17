package lateral

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/masterzen/winrm"
	"github.com/masterzen/winrm/soap"
)

func TestPTHDiagnose_NamedLayers(t *testing.T) {
	layers := []PTHLayer{
		PTHLayerTransport, PTHLayerHTTPNegotiate, PTHLayerNTLMHandshake,
		PTHLayerKeyDerivation, PTHLayerSignSeal, PTHLayerWinRMMIME, PTHLayerSessionLife,
	}
	for _, want := range layers {
		err := pthWrap(want, fmt.Errorf("boom"))
		got, ok := PTHDiagnose(err)
		if !ok || got != want {
			t.Fatalf("diagnose %s: got %q ok=%v", want, got, ok)
		}
		if !strings.Contains(err.Error(), "pth_layer="+string(want)) {
			t.Fatalf("error string missing layer: %v", err)
		}
	}
	if _, ok := PTHDiagnose(fmt.Errorf("unclassified")); ok {
		t.Fatal("plain error should not diagnose")
	}
	// No double-wrap.
	inner := pthWrap(PTHLayerSignSeal, fmt.Errorf("rc4"))
	outer := pthWrap(PTHLayerTransport, inner)
	got, ok := PTHDiagnose(outer)
	if !ok || got != PTHLayerSignSeal {
		t.Fatalf("kept inner layer, got %q ok=%v", got, ok)
	}
}

func TestPTHPool_SameKeyReusesSlot(t *testing.T) {
	resetPTHPoolForTest()
	t.Cleanup(resetPTHPoolForTest)
	a := acquirePTHSlot(pthSessionKey("10.0.0.1", `DOM\u`, "aa"))
	b := acquirePTHSlot(pthSessionKey("10.0.0.1", `DOM\u`, "aa"))
	if a != b {
		t.Fatal("same key must return the same slot")
	}
	c := acquirePTHSlot(pthSessionKey("10.0.0.2", `DOM\u`, "aa"))
	if c == a {
		t.Fatal("different target must be a new slot")
	}
}

func TestPTHHash_HandshakeOnceThenThreeSOAP(t *testing.T) {
	var type1, soapPosts int
	var authed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			if authed {
				soapPosts++
				w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
				_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`))
				return
			}
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := decodeNTLMAuth(auth)
		if err != nil || len(raw) < 12 {
			http.Error(w, "bad ntlm", http.StatusUnauthorized)
			return
		}
		typ := binary.LittleEndian.Uint32(raw[8:12])
		switch typ {
		case 1:
			type1++
			w.Header().Set("Www-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(testNTLMType2NoSeal()))
			w.WriteHeader(http.StatusUnauthorized)
		case 3:
			authed = true
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "unexpected ntlm type", http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)

	c := newClientNTLMWithHash(`LAB\alice`, "603fc24ee01a9409f83c9d1d701485c5")
	if err := c.Transport(endpointFromURL(t, srv.URL)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Post(nil, soap.NewMessage()); err != nil {
			t.Fatalf("post %d: %v", i+1, err)
		}
	}
	st := c.statsSnapshot()
	if type1 != 1 {
		t.Fatalf("NTLM TYPE1 count=%d want 1 (renegotiated)", type1)
	}
	if st.AuthProbes != 1 {
		t.Fatalf("auth probes=%d want 1", st.AuthProbes)
	}
	if st.SOAPPosts != 3 {
		t.Fatalf("SOAP posts=%d want 3", st.SOAPPosts)
	}
	if st.NTLMRounds != 1 {
		t.Fatalf("NTLM rounds=%d want 1", st.NTLMRounds)
	}
}

func TestPTHHash_401WithoutNegotiateIsHTTPLayer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := newClientNTLMWithHash(`LAB\alice`, "603fc24ee01a9409f83c9d1d701485c5")
	if err := c.Transport(endpointFromURL(t, srv.URL)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Post(nil, soap.NewMessage())
	layer, ok := PTHDiagnose(err)
	if !ok || layer != PTHLayerHTTPNegotiate {
		t.Fatalf("got layer=%q ok=%v err=%v", layer, ok, err)
	}
}

func TestPTHHash_NoPlainRetryOn415(t *testing.T) {
	var posts int
	var authed bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			if authed {
				posts++
				w.WriteHeader(http.StatusUnsupportedMediaType)
				_, _ = w.Write([]byte("encryption required"))
				return
			}
			w.Header().Set("Www-Authenticate", "NTLM")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		raw, err := decodeNTLMAuth(auth)
		if err != nil || len(raw) < 12 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		typ := binary.LittleEndian.Uint32(raw[8:12])
		if typ == 1 {
			w.Header().Set("Www-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(testNTLMType2NoSeal()))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if typ == 3 {
			authed = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	c := newClientNTLMWithHash(`LAB\alice`, "603fc24ee01a9409f83c9d1d701485c5")
	if err := c.Transport(endpointFromURL(t, srv.URL)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Post(nil, soap.NewMessage())
	if err == nil {
		t.Fatal("expected 415 to fail once")
	}
	if posts != 1 {
		t.Fatalf("SOAP posts=%d want 1 (no seal→plain retry)", posts)
	}
	layer, ok := PTHDiagnose(err)
	if !ok || layer != PTHLayerWinRMMIME {
		t.Fatalf("got layer=%q ok=%v err=%v", layer, ok, err)
	}
}

func decodeNTLMAuth(h string) ([]byte, error) {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return nil, io.EOF
	}
	return base64.StdEncoding.DecodeString(parts[1])
}

func testNTLMType2NoSeal() []byte {
	msg := make([]byte, 48)
	copy(msg[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(msg[8:12], 2)
	flags := ntlmFlagUnicode | ntlmFlagNTLM | ntlmFlagExtendedSessionSecurity | ntlmFlag128
	binary.LittleEndian.PutUint32(msg[20:24], flags)
	copy(msg[24:32], []byte("CHALLENG"))
	return msg
}

func endpointFromURL(t *testing.T, raw string) *winrm.Endpoint {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return winrm.NewEndpoint(u.Hostname(), port, u.Scheme == "https", true, nil, nil, nil, 0)
}
