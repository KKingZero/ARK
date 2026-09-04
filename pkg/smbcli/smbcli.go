// Package smbcli is a host-side SMB2 client (no implant session).
package smbcli

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"
	"time"

	"github.com/KKingZero/ARK/pkg/netproxy"
	"github.com/hirochachacha/go-smb2"
)

const dialTimeout = 15 * time.Second

const maxDownloadBytes = 10 << 20

// Options for SMB auth.
type Options struct {
	Host      string
	Domain    string
	Username  string
	Password  string
	Hash      string
	Anonymous bool
	// Ticket is a ticket-store id or ccache/kirbi path.
	// Kerberos SMB is native (DialKerberos). Impacket smbclient.py -k
	// remains behind ARK_SMB_IMPACKET=1.
	Ticket string
}

// Session is a logged-on SMB2 session.
type Session struct {
	inner *smb2.Session
	kerb  *krbSession
	host  string
}

// Dial authenticates to host:445.
func Dial(opts Options) (*Session, error) {
	if UseTicket(opts) {
		if ticketNativeEnabled() {
			return DialKerberos(opts)
		}
		return nil, fmt.Errorf("smb Dial is NTLM-only; set ARK_SMB_IMPACKET=0 for native Kerberos")
	}
	if opts.Host == "" {
		return nil, fmt.Errorf("host required")
	}
	addr := joinSMBAddr(opts.Host)
	conn, err := netproxy.DialTimeout("tcp", addr, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("smb connect %s: %w", addr, err)
	}
	init, err := initiator(opts)
	if err != nil {
		conn.Close()
		return nil, err
	}
	s, err := (&smb2.Dialer{Initiator: init}).Dial(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smb auth: %w", err)
	}
	return &Session{inner: s, host: opts.Host}, nil
}

// SessionKey is the Kerberos SMB session key (nil for NTLM go-smb2).
func (s *Session) SessionKey() []byte {
	if s == nil || s.kerb == nil {
		return nil
	}
	return append([]byte(nil), s.kerb.sessionKey...)
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	if s.kerb != nil {
		return s.kerb.Close()
	}
	if s.inner == nil {
		return nil
	}
	return s.inner.Logoff()
}

// ListShares returns share names.
func (s *Session) ListShares() ([]string, error) {
	if s.kerb != nil {
		return s.kerb.ListShares()
	}
	names, err := s.inner.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("list shares: %w", err)
	}
	return names, nil
}

// ListDir lists share path (empty path = root).
func (s *Session) ListDir(share, p string) ([]string, error) {
	if share == "" {
		return nil, fmt.Errorf("share required")
	}
	if s.kerb != nil {
		return s.kerb.ListDir(share, p)
	}
	sh, err := s.inner.Mount(uncShare(s.host, share))
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", share, err)
	}
	defer sh.Umount()
	dir := NormalizePath(p)
	entries, err := sh.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("readdir %s: %w", dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		out = append(out, name)
	}
	return out, nil
}

// Download reads a file (max 10 MiB).
func (s *Session) Download(share, p string) ([]byte, error) {
	if share == "" || p == "" {
		return nil, fmt.Errorf("share and path required")
	}
	if s.kerb != nil {
		return s.kerb.Download(share, p)
	}
	sh, err := s.inner.Mount(uncShare(s.host, share))
	if err != nil {
		return nil, fmt.Errorf("mount %s: %w", share, err)
	}
	defer sh.Umount()
	filePath := NormalizePath(p)
	f, err := sh.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxDownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDownloadBytes {
		return nil, fmt.Errorf("file too large: max %d bytes", maxDownloadBytes)
	}
	return data, nil
}

// DownloadTo writes a remote file to destPath (or stdout if destPath is "-"/empty after print).
func DownloadTo(opts Options, share, remote, destPath string) error {
	if UseTicket(opts) && !ticketNativeEnabled() {
		return TicketDownload(opts, share, remote, destPath)
	}
	s, err := Dial(opts)
	if err != nil {
		return err
	}
	defer s.Close()
	data, err := s.Download(share, remote)
	if err != nil {
		return err
	}
	if destPath == "" || destPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(destPath, data, 0o600)
}

func initiator(opts Options) (*smb2.NTLMInitiator, error) {
	if opts.Ticket != "" && opts.Hash == "" {
		return nil, fmt.Errorf("smb Dial is NTLM-only; Kerberos uses DialKerberos")
	}
	if opts.Anonymous || (opts.Username == "" && opts.Password == "" && opts.Hash == "") {
		return &smb2.NTLMInitiator{}, nil
	}
	if opts.Username == "" {
		return nil, fmt.Errorf("username required (or --anon)")
	}
	init := &smb2.NTLMInitiator{
		User:     opts.Username,
		Domain:   opts.Domain,
		Password: opts.Password,
	}
	if strings.Contains(init.User, `\`) {
		parts := strings.SplitN(init.User, `\`, 2)
		if init.Domain == "" {
			init.Domain = parts[0]
		}
		init.User = parts[1]
	}
	if opts.Hash != "" {
		h, err := ParseNTHash(opts.Hash)
		if err != nil {
			return nil, err
		}
		init.Hash = h
		init.Password = ""
	} else if opts.Password == "" {
		return nil, fmt.Errorf("password or hash required (or --anon)")
	}
	return init, nil
}

// ParseNTHash accepts 32-hex NT or LM:NT / 64-hex.
func ParseNTHash(hashHex string) ([]byte, error) {
	hashHex = strings.TrimSpace(strings.ToLower(hashHex))
	if strings.Contains(hashHex, ":") {
		parts := strings.SplitN(hashHex, ":", 2)
		hashHex = parts[0] + parts[1]
	}
	if len(hashHex) == 32 {
		hashHex = "aad3b435b51404eeaad3b435b51404ee" + hashHex
	}
	if len(hashHex) != 64 {
		return nil, fmt.Errorf("ntlm hash must be 32 or 64 hex characters")
	}
	return hex.DecodeString(hashHex)
}

func joinSMBAddr(host string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return net.JoinHostPort("127.0.0.1", "445")
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, "445")
}

func uncShare(host, share string) string {
	share = strings.Trim(share, `\`)
	return `\\` + host + `\` + share
}

// NormalizePath converts a share-relative path for go-smb2.
func NormalizePath(p string) string {
	p = strings.ReplaceAll(p, `/`, `\`)
	p = strings.TrimPrefix(p, `\`)
	if p == "" || p == "." {
		return "."
	}
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}
