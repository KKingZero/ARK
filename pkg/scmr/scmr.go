// Package scmr is a host-side MS-SCMR client over an existing SMB session.
// The implant does not call this package.
package scmr

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/KKingZero/ARK/pkg/smbcli"
)

const (
	opCloseServiceHandle = 0
	opCreateServiceW     = 12
	opOpenSCManagerW     = 15
	opStartServiceW      = 19

	accessSCManagerAll = 0x000F003F
	accessServiceAll   = 0x000F01FF
	serviceWin32Own    = 0x00000010
	startDemand        = 3

	maxFrag = 0xffe8
)

// scmrUUID is 367ABB81-9844-35F1-AD32-98F038001003.
var scmrUUID = []byte{
	0x81, 0xBB, 0x7A, 0x36, 0x44, 0x98, 0xF1, 0x35,
	0xAD, 0x32, 0x98, 0xF0, 0x38, 0x00, 0x10, 0x03,
}

// CreateAndStart opens the service manager, creates a demand-start service,
// starts it, and closes both handles. It does not delete the service.
func CreateAndStart(s *smbcli.Session, machine, service, binPath string) error {
	if s == nil {
		return fmt.Errorf("smb session required")
	}
	if machine == "" || service == "" || binPath == "" {
		return fmt.Errorf("machine, service, and binary path required")
	}
	p, err := s.OpenPipe("svcctl")
	if err != nil {
		return err
	}
	defer p.Close()
	c := &client{pipe: p, call: 2}
	ack, err := p.Transceive(dcerpcBind(1, scmrUUID, 2))
	if err != nil {
		return fmt.Errorf("svcctl bind: %w", err)
	}
	if len(ack) < 3 || ack[2] != 12 {
		return fmt.Errorf("svcctl bind ack type=%d (want 12)", bAt(ack, 2))
	}
	body, err := c.rpc(opOpenSCManagerW, encodeOpenSCManagerW(machine))
	if err != nil {
		return fmt.Errorf("OpenSCManagerW: %w", err)
	}
	scm, st := parseTrailingHandle(body)
	if st != 0 {
		return win32Err("OpenSCManagerW", st)
	}
	body, err = c.rpc(opCreateServiceW, encodeCreateServiceW(scm, service, binPath))
	if err != nil {
		_, _ = c.rpc(opCloseServiceHandle, encodeCloseService(scm))
		return fmt.Errorf("CreateServiceW: %w", err)
	}
	svc, st := parseTrailingHandle(body)
	if st != 0 {
		_, _ = c.rpc(opCloseServiceHandle, encodeCloseService(scm))
		return win32Err("CreateServiceW", st)
	}
	body, err = c.rpc(opStartServiceW, encodeStartServiceW(svc))
	if err != nil {
		_, _ = c.rpc(opCloseServiceHandle, encodeCloseService(svc))
		_, _ = c.rpc(opCloseServiceHandle, encodeCloseService(scm))
		return fmt.Errorf("StartServiceW: %w", err)
	}
	st = trailingStatus(body)
	_, _ = c.rpc(opCloseServiceHandle, encodeCloseService(svc))
	_, _ = c.rpc(opCloseServiceHandle, encodeCloseService(scm))
	if st != 0 {
		return win32Err("StartServiceW", st)
	}
	return nil
}

func win32Err(op string, code uint32) error {
	return fmt.Errorf("%s win32=%d", op, code)
}

type client struct {
	pipe *smbcli.Pipe
	call uint32
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
	return rpcStub(resp)
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
		return nil, fmt.Errorf("scmr stub too large (%d)", n)
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
	h := append([]byte(nil), body[len(body)-24:len(body)-4]...)
	return h, st
}

func bAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}

// lpMachineName is a top-level unique LPWSTR (MS-SCMR SVCCTL_HANDLEW).
// The referent is inlined after the pointer id, which is what Windows accepts
// for this call. lpDatabaseName is a unique NULL.
func encodeOpenSCManagerW(machine string) []byte {
	n := ndr{}
	n.u32(0x00020000)
	n.wstr(machine)
	n.u32(0)
	n.u32(accessSCManagerAll)
	return n.b
}

// lpServiceName and lpBinaryPathName are top-level ref WSTRs.
// lpDisplayName and the group, tag, dependency, account, and password
// pointers are unique NULL.
func encodeCreateServiceW(handle []byte, service, binPath string) []byte {
	n := ndr{}
	n.bytes(handle)
	n.wstr(service)
	n.u32(0)
	n.u32(accessServiceAll)
	n.u32(serviceWin32Own)
	n.u32(startDemand)
	n.u32(0)
	n.wstr(binPath)
	for i := 0; i < 7; i++ {
		n.u32(0)
	}
	return n.b
}

func encodeStartServiceW(handle []byte) []byte {
	n := ndr{}
	n.bytes(handle)
	n.u32(0)
	n.u32(0)
	return n.b
}

func encodeCloseService(handle []byte) []byte {
	n := ndr{}
	n.bytes(handle)
	return n.b
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
func (n *ndr) align4() {
	for len(n.b)%4 != 0 {
		n.b = append(n.b, 0)
	}
}
func (n *ndr) bytes(p []byte) { n.b = append(n.b, p...) }

func (n *ndr) wstr(s string) {
	n.align4()
	u := utf16.Encode([]rune(s))
	if len(u) == 0 || u[len(u)-1] != 0 {
		u = append(u, 0)
	}
	n.u32(uint32(len(u)))
	n.u32(0)
	n.u32(uint32(len(u)))
	for _, r := range u {
		n.u16(r)
	}
	n.align4()
}
