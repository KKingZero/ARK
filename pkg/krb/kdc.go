package krb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/netproxy"
)

const kdcTimeout = 15 * time.Second

// SendKDC sends a Kerberos message to host:88 over TCP (4-byte length prefix).
// Honors ARK_PROXY / ALL_PROXY via netproxy.
func SendKDC(kdc string, msg []byte) ([]byte, error) {
	kdc = trimKDCHost(kdc)
	if kdc == "" || len(msg) == 0 {
		return nil, fmt.Errorf("kdc and message required")
	}
	host, port := kdc, 88
	if h, p, err := net.SplitHostPort(kdc); err == nil {
		host = h
		if n, conv := strconv.Atoi(p); conv == nil && n > 0 {
			port = n
		}
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := netproxy.DialTimeout("tcp", addr, kdcTimeout)
	if err != nil {
		return nil, fmt.Errorf("kdc %s: %w", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(kdcTimeout))
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(msg)))
	if _, err := conn.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("kdc write hdr: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, fmt.Errorf("kdc write: %w", err)
	}
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("kdc read hdr: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 1<<20 {
		return nil, fmt.Errorf("kdc reply length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("kdc read: %w", err)
	}
	return body, nil
}

func trimKDCHost(kdc string) string {
	kdc = trimURI(kdc)
	return kdc
}

func trimURI(s string) string {
	lower := strings.ToLower(s)
	for _, p := range []string{"ldaps://", "ldap://", "tcp://"} {
		if strings.HasPrefix(lower, p) {
			return s[len(p):]
		}
	}
	return s
}
