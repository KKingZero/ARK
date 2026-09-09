// Package samr is a host-side MS-SAMR client over SMB IPC$ (no implant).
package samr

import (
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/KKingZero/ARK/pkg/smbcli"
	"golang.org/x/crypto/md4"
)

// samr UUID 12345778-1234-ABCD-EF00-0123456789AC
var samrUUID = []byte{0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac}

const (
	samrVersion              = 1
	opCloseHandle            = 1
	opLookupDomain           = 5
	opOpenDomain             = 7
	opLookupNames            = 17
	opOpenUser               = 34
	opCreateUser2            = 50
	opSetInformationUser2    = 58
	opConnect5               = 64
	accessMaxAllowed         = 0x02000000
	ufWorkstation            = 0x00001000 // UF_WORKSTATION_TRUST_ACCOUNT
	userInternal1Information = 18
	maxFrag                  = 0xffe8
)

// CreateWorkstation creates a machine account via SAMR (LDAP Add already failed).
func CreateWorkstation(s *smbcli.Session, domain, name, password string) (string, error) {
	if s == nil {
		return "", fmt.Errorf("smb session required")
	}
	sam, err := sanitizeComputer(name)
	if err != nil {
		return "", err
	}
	c, err := bindSAMR(s)
	if err != nil {
		return "", err
	}
	defer c.closeAll()
	if err := c.connect(); err != nil {
		return "", err
	}
	if err := c.lookupOpenDomain(domain); err != nil {
		return "", err
	}
	if err := c.createUser2(sam, ufWorkstation); err != nil {
		return "", err
	}
	if password != "" {
		if err := c.setPassword(password); err != nil {
			return "", fmt.Errorf("created %s but set password failed: %w", sam, err)
		}
	}
	return sam, nil
}

// SetPassword resets a user's password via SAMR (no old password).
func SetPassword(s *smbcli.Session, domain, targetSAM, newPass string) error {
	if s == nil {
		return fmt.Errorf("smb session required")
	}
	if targetSAM == "" || newPass == "" {
		return fmt.Errorf("target and new password required")
	}
	c, err := bindSAMR(s)
	if err != nil {
		return err
	}
	defer c.closeAll()
	if err := c.connect(); err != nil {
		return err
	}
	if err := c.lookupOpenDomain(domain); err != nil {
		return err
	}
	if err := c.openUserByName(targetSAM); err != nil {
		return err
	}
	return c.setPassword(newPass)
}

type client struct {
	pipe       *smbcli.Pipe
	call       uint32
	serverH    []byte
	domainH    []byte
	userH      []byte
	sessionKey []byte
}

func bindSAMR(s *smbcli.Session) (*client, error) {
	p, err := s.OpenPipe("samr")
	if err != nil {
		return nil, err
	}
	c := &client{pipe: p, call: 2, sessionKey: s.SessionKey()}
	bind := dcerpcBind(1, samrUUID, samrVersion)
	ack, err := p.Transceive(bind)
	if err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("samr bind: %w", err)
	}
	if len(ack) < 3 || ack[2] != 12 {
		_ = p.Close()
		return nil, fmt.Errorf("samr bind ack type=%d (want 12)", bAt(ack, 2))
	}
	return c, nil
}

func (c *client) rpc(opnum uint16, stub []byte) ([]byte, error) {
	req, err := dcerpcRequest(c.call, opnum, stub)
	if err != nil {
		return nil, err
	}
	c.call++
	resp, err := c.pipe.Transceive(req)
	if err != nil {
		return nil, err
	}
	body, err := rpcStub(resp)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (c *client) connect() error {
	stub := encodeConnect5("\\\\", accessMaxAllowed)
	body, err := c.rpc(opConnect5, stub)
	if err != nil {
		return fmt.Errorf("SamrConnect5: %w", err)
	}
	h, st := parseTrailingHandle(body)
	if st != 0 {
		return fmt.Errorf("SamrConnect5 ntstatus=0x%08x", st)
	}
	if len(h) != 20 {
		return fmt.Errorf("SamrConnect5: no server handle")
	}
	c.serverH = h
	return nil
}

func (c *client) lookupOpenDomain(domain string) error {
	netbios := domainNetBIOS(domain)
	stub := ndr{}
	stub.bytes(c.serverH)
	stub.rpcUnicodeString(netbios)
	body, err := c.rpc(opLookupDomain, stub.b)
	if err != nil {
		return fmt.Errorf("SamrLookupDomain: %w", err)
	}
	sid, st := parseSIDAndStatus(body)
	if st != 0 {
		return fmt.Errorf("SamrLookupDomain ntstatus=0x%08x", st)
	}
	open := ndr{}
	open.bytes(c.serverH)
	open.u32(accessMaxAllowed)
	open.uniqueSID(sid)
	body, err = c.rpc(opOpenDomain, open.b)
	if err != nil {
		return fmt.Errorf("SamrOpenDomain: %w", err)
	}
	h, st := parseTrailingHandle(body)
	if st != 0 {
		return fmt.Errorf("SamrOpenDomain ntstatus=0x%08x", st)
	}
	c.domainH = h
	return nil
}

func (c *client) createUser2(sam string, acct uint32) error {
	stub := ndr{}
	stub.bytes(c.domainH)
	stub.rpcUnicodeString(sam)
	stub.u32(acct)
	stub.u32(accessMaxAllowed)
	body, err := c.rpc(opCreateUser2, stub.b)
	if err != nil {
		return fmt.Errorf("SamrCreateUser2InDomain: %w", err)
	}
	h, st := parseTrailingHandle(body)
	if st != 0 {
		return fmt.Errorf("SamrCreateUser2InDomain ntstatus=0x%08x", st)
	}
	c.userH = h
	return nil
}

func (c *client) openUserByName(sam string) error {
	stub := ndr{}
	stub.bytes(c.domainH)
	stub.u32(1)
	stub.rpcUnicodeString(sam)
	body, err := c.rpc(opLookupNames, stub.b)
	if err != nil {
		return fmt.Errorf("SamrLookupNames: %w", err)
	}
	rid, st := parseLookupRID(body)
	if st != 0 {
		return fmt.Errorf("SamrLookupNames ntstatus=0x%08x", st)
	}
	open := ndr{}
	open.bytes(c.domainH)
	open.u32(accessMaxAllowed)
	open.u32(rid)
	body, err = c.rpc(opOpenUser, open.b)
	if err != nil {
		return fmt.Errorf("SamrOpenUser: %w", err)
	}
	h, st := parseTrailingHandle(body)
	if st != 0 {
		return fmt.Errorf("SamrOpenUser ntstatus=0x%08x", st)
	}
	c.userH = h
	return nil
}

func (c *client) setPassword(password string) error {
	if len(c.sessionKey) == 0 {
		return fmt.Errorf("SAMR set-password needs a Kerberos SMB session key (asktgt then --ticket); NTLM go-smb2 has no exported key")
	}
	if len(c.userH) != 20 {
		return fmt.Errorf("SAMR user handle missing")
	}
	nt := ntHash(password)
	key := c.sessionKey
	if len(key) > 16 {
		key = key[:16]
	}
	enc, err := rc4Encrypt(key, nt)
	if err != nil {
		return err
	}
	stub := ndr{}
	stub.bytes(c.userH)
	stub.u32(userInternal1Information)
	stub.bytes(enc)
	stub.pad(16)
	stub.b = append(stub.b, 1, 0, 0)
	stub.align4()
	body, err := c.rpc(opSetInformationUser2, stub.b)
	if err != nil {
		return fmt.Errorf("SamrSetInformationUser2: %w", err)
	}
	st := trailingStatus(body)
	if st != 0 {
		return fmt.Errorf("SamrSetInformationUser2 ntstatus=0x%08x", st)
	}
	return nil
}

func (c *client) closeAll() {
	for _, h := range [][]byte{c.userH, c.domainH, c.serverH} {
		if len(h) != 20 {
			continue
		}
		stub := ndr{}
		stub.bytes(h)
		_, _ = c.rpc(opCloseHandle, stub.b)
	}
	if c.pipe != nil {
		_ = c.pipe.Close()
		c.pipe = nil
	}
}

func sanitizeComputer(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "$")
	if name == "" {
		return "", fmt.Errorf("computer name required")
	}
	return name + "$", nil
}

func domainNetBIOS(domain string) string {
	domain = strings.TrimSpace(domain)
	if i := strings.IndexByte(domain, '.'); i > 0 {
		return strings.ToUpper(domain[:i])
	}
	return strings.ToUpper(domain)
}

func ntHash(password string) []byte {
	u := utf16.Encode([]rune(password))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	sum := md4.New()
	sum.Write(b)
	return sum.Sum(nil)
}

func rc4Encrypt(key, pt []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(pt))
	c.XORKeyStream(out, pt)
	return out, nil
}

func dcerpcBind(callID uint32, iface []byte, ver uint16) []byte {
	b := make([]byte, 72)
	b[0], b[1], b[2], b[3] = 5, 0, 11, 0x03
	b[4] = 0x10
	binary.LittleEndian.PutUint16(b[8:10], 72)
	binary.LittleEndian.PutUint32(b[12:16], callID)
	binary.LittleEndian.PutUint16(b[16:18], 4280)
	binary.LittleEndian.PutUint16(b[18:20], 4280)
	binary.LittleEndian.PutUint32(b[24:28], 1)
	binary.LittleEndian.PutUint16(b[30:32], 1)
	copy(b[32:48], iface)
	binary.LittleEndian.PutUint16(b[48:50], ver)
	ndrSyn := []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	copy(b[52:68], ndrSyn)
	binary.LittleEndian.PutUint32(b[68:72], 2)
	return b
}

func dcerpcRequest(callID uint32, opnum uint16, stub []byte) ([]byte, error) {
	n := 24 + len(stub)
	if n > maxFrag {
		return nil, fmt.Errorf("samr stub too large (%d)", n)
	}
	hdr := make([]byte, 24)
	hdr[0], hdr[1], hdr[2], hdr[3] = 5, 0, 0, 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(n))
	binary.LittleEndian.PutUint32(hdr[12:16], callID)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(stub)))
	binary.LittleEndian.PutUint16(hdr[22:24], opnum)
	return append(hdr, stub...), nil
}

func rpcStub(resp []byte) ([]byte, error) {
	if len(resp) < 24 {
		return nil, fmt.Errorf("rpc response short (%d)", len(resp))
	}
	if resp[2] != 2 {
		return nil, fmt.Errorf("rpc ptype=%d (want 2 response)", resp[2])
	}
	return resp[24:], nil
}

func trailingStatus(body []byte) uint32 {
	if len(body) < 4 {
		return 0xffffffff
	}
	return binary.LittleEndian.Uint32(body[len(body)-4:])
}

func parseTrailingHandle(body []byte) ([]byte, uint32) {
	st := trailingStatus(body)
	if st != 0 || len(body) < 24 {
		return nil, st
	}
	// handle is 20 bytes immediately before NTSTATUS
	h := append([]byte(nil), body[len(body)-24:len(body)-4]...)
	return h, st
}

func parseSIDAndStatus(body []byte) ([]byte, uint32) {
	st := trailingStatus(body)
	if st != 0 {
		return nil, st
	}
	if len(body) < 12 {
		return nil, 0xffffffff
	}
	off := 0
	if binary.LittleEndian.Uint32(body[0:4]) != 0 {
		off = 4
	}
	rest := body[off : len(body)-4]
	if len(rest) < 8 {
		return nil, 0xffffffff
	}
	nsub := int(rest[1])
	need := 8 + 4*nsub
	if nsub < 1 || nsub > 15 || len(rest) < need {
		return nil, 0xffffffff
	}
	return rest[:need], st
}

func parseLookupRID(body []byte) (uint32, uint32) {
	st := trailingStatus(body)
	if st != 0 {
		return 0, st
	}
	// SAMPR_ULONG_ARRAY: Count, unique ptr, max, RID[0], …
	if len(body) < 20 {
		return 0, 0xffffffff
	}
	count := binary.LittleEndian.Uint32(body[0:4])
	if count == 0 {
		return 0, st
	}
	return binary.LittleEndian.Uint32(body[12:16]), st
}

func bAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}

type ndr struct{ b []byte }

func (n *ndr) u16(v uint16) {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	n.b = append(n.b, t[:]...)
}
func (n *ndr) u32(v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	n.b = append(n.b, t[:]...)
}
func (n *ndr) pad(k int) { n.b = append(n.b, make([]byte, k)...) }
func (n *ndr) align4() {
	for len(n.b)%4 != 0 {
		n.b = append(n.b, 0)
	}
}
func (n *ndr) bytes(p []byte) { n.b = append(n.b, p...) }
func (n *ndr) rpcUnicode(s string) {
	n.align4()
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	n.u32(uint32(len(u))) // max
	n.u32(0)              // offset
	n.u32(uint32(len(u))) // actual
	for _, r := range u {
		var t [2]byte
		binary.LittleEndian.PutUint16(t[:], r)
		n.b = append(n.b, t[:]...)
	}
	n.align4()
}
func (n *ndr) uniqueSID(raw []byte) {
	n.align4()
	n.u32(0x20000)
	n.bytes(raw)
	n.align4()
}

func (n *ndr) rpcUnicodeString(s string) {
	n.align4()
	u := utf16.Encode([]rune(s))
	byteLen := len(u) * 2
	n.u16(uint16(byteLen))
	n.u16(uint16(byteLen + 2))
	n.u32(0x20000)
	n.u32(uint32(len(u) + 1))
	n.u32(0)
	n.u32(uint32(len(u) + 1))
	for _, r := range u {
		var t [2]byte
		binary.LittleEndian.PutUint16(t[:], r)
		n.b = append(n.b, t[:]...)
	}
	n.b = append(n.b, 0, 0)
	n.align4()
}

func encodeConnect5(server string, access uint32) []byte {
	n := ndr{}
	n.u32(0x20000) // unique ptr ServerName
	n.rpcUnicode(server)
	n.u32(access)
	n.u32(1) // InVersion
	n.u32(1) // union arm V1
	n.u32(3) // Revision
	n.u32(0) // SupportedFeatures
	return n.b
}
