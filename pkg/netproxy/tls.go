package netproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"time"
)

// TLSMode selects how a lab TLS dial treats the peer certificate.
type TLSMode int

const (
	// TLSVerifyThenFallback verifies with roots (the system roots when nil).
	// A certificate error opens a second connection with verification disabled.
	TLSVerifyThenFallback TLSMode = iota
	// TLSInsecure skips verification.
	TLSInsecure
	// TLSStrict returns a certificate error. It does not fall back.
	TLSStrict
)

// tlsLogf is the lab TLS notice. Tests replace it.
var tlsLogf = log.Printf

// DialTLS dials addr and completes a TLS handshake.
// roots is the trust pool for the verifying attempt. Nil uses the system roots.
// The caller closes the returned connection.
func DialTLS(addr, serverName string, roots *x509.CertPool, mode TLSMode) (*tls.Conn, error) {
	switch mode {
	case TLSInsecure:
		tlsLogf("[ldaps] %s: verification skipped", addr)
		return dialTLSOnce(addr, serverName, roots, true)
	case TLSStrict:
		return dialTLSOnce(addr, serverName, roots, false)
	default:
		conn, err := dialTLSOnce(addr, serverName, roots, false)
		if err == nil || !certVerifyError(err) {
			return conn, err
		}
		tlsLogf("[ldaps] %s: certificate not trusted, retrying without verification", addr)
		return dialTLSOnce(addr, serverName, roots, true)
	}
}

func dialTLSOnce(addr, serverName string, roots *x509.CertPool, skip bool) (*tls.Conn, error) {
	raw, err := DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("ldaps %s: %w", addr, err)
	}
	tlsConn := tls.Client(raw, &tls.Config{
		InsecureSkipVerify: skip,
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		RootCAs:            roots,
	})
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("ldaps handshake %s: %w", addr, err)
	}
	return tlsConn, nil
}

func certVerifyError(err error) bool {
	var (
		unknown   x509.UnknownAuthorityError
		host      x509.HostnameError
		invalid   x509.CertificateInvalidError
		tlsVerify *tls.CertificateVerificationError
	)
	return errors.As(err, &unknown) || errors.As(err, &host) || errors.As(err, &invalid) || errors.As(err, &tlsVerify)
}
