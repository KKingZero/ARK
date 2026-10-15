package netproxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return cert, pool
}

func serveSelfSigned(t *testing.T, cert tls.Certificate) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepts atomic.Int32
	var mu sync.Mutex
	var open []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			sc := tls.Server(c, &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			})
			mu.Lock()
			open = append(open, sc)
			mu.Unlock()
			go func() { _ = sc.Handshake() }()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range open {
			c.Close()
		}
	})
	return ln.Addr().String(), &accepts
}

func TestDialTLSModes(t *testing.T) {
	cert, pool := testCert(t)
	var notes []string
	prev := tlsLogf
	tlsLogf = func(format string, args ...any) {
		notes = append(notes, fmt.Sprintf(format, args...))
	}
	t.Cleanup(func() { tlsLogf = prev })

	addr, accepts := serveSelfSigned(t, cert)
	conn, err := DialTLS(addr, "127.0.0.1", nil, TLSVerifyThenFallback)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if accepts.Load() != 2 {
		t.Fatalf("fallback accepts=%d", accepts.Load())
	}
	if !strings.Contains(strings.Join(notes, "\n"), "retrying without verification") {
		t.Fatalf("log %q", notes)
	}

	notes = nil
	addr, accepts = serveSelfSigned(t, cert)
	conn, err = DialTLS(addr, "127.0.0.1", pool, TLSVerifyThenFallback)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if accepts.Load() != 1 {
		t.Fatalf("trusted accepts=%d", accepts.Load())
	}
	if len(notes) != 0 {
		t.Fatalf("trusted logged %q", notes)
	}

	addr, accepts = serveSelfSigned(t, cert)
	if _, err := DialTLS(addr, "127.0.0.1", nil, TLSStrict); err == nil {
		t.Fatal("strict accepted a self-signed certificate")
	}
	if accepts.Load() != 1 {
		t.Fatalf("strict accepts=%d", accepts.Load())
	}
}
