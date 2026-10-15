package krb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFetchDCTimeSelfSignedFallsBack(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
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
			sc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
			mu.Lock()
			open = append(open, sc)
			mu.Unlock()
			go func() {
				_ = sc.Handshake()
				sc.Close()
			}()
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

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = FetchDCTime("ldaps://127.0.0.1:"+port, "", "")
	if err == nil {
		t.Fatal("expected an LDAP error from a TLS-only peer")
	}
	if strings.Contains(err.Error(), "handshake") {
		t.Fatalf("handshake failed instead of falling back: %v", err)
	}
	if accepts.Load() != 2 {
		t.Fatalf("accepts=%d err=%v", accepts.Load(), err)
	}
}
