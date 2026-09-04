package krb

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	pacLogonInfo        uint32 = 1
	pacClientInfo       uint32 = 10
	pacServerChecksum   uint32 = 6
	pacKDCChecksum      uint32 = 7
	pacVersion                 = 0
	groupAttrDefault    uint32 = 7
	uacNormalDontExpire        = 0x210
	neverTime           uint64 = 0x7fffffffffffffff
)

// PACUser is the logon-info we put in a golden/silver PAC.
type PACUser struct {
	User      string
	Domain    string // NetBIOS or DNS; PAC uses short name
	DomainSID string
	RID       uint32
	Groups    []uint32
	AuthTime  time.Time
}

// DefaultGoldenGroups is DA + Domain Users + schema/enterprise/group-policy.
func DefaultGoldenGroups() []uint32 {
	return []uint32{513, 512, 518, 519, 520}
}

// BuildPAC is a signed PAC (server + KDC checksums) over krbtgt/service AES key.
func BuildPAC(u PACUser, key types.EncryptionKey) ([]byte, error) {
	if u.RID == 0 {
		u.RID = 500
	}
	if len(u.Groups) == 0 {
		u.Groups = DefaultGoldenGroups()
	}
	if u.AuthTime.IsZero() {
		u.AuthTime = Now()
	}
	logon, err := marshalLogonInfo(u)
	if err != nil {
		return nil, err
	}
	client := marshalClientInfo(u.User, u.AuthTime)
	sigLen := 4 + 12 // type + AES256 checksum
	bufs := []pacBuf{
		{typ: pacLogonInfo, data: logon},
		{typ: pacClientInfo, data: client},
		{typ: pacServerChecksum, data: make([]byte, sigLen)},
		{typ: pacKDCChecksum, data: make([]byte, sigLen)},
	}
	binary.LittleEndian.PutUint32(bufs[2].data[0:4], uint32(chksumtype.HMAC_SHA1_96_AES256))
	binary.LittleEndian.PutUint32(bufs[3].data[0:4], uint32(chksumtype.HMAC_SHA1_96_AES256))
	raw := packPAC(bufs)
	et, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	if key.KeyType != etypeID.AES256_CTS_HMAC_SHA1_96 && key.KeyType != etypeID.AES128_CTS_HMAC_SHA1_96 {
		return nil, fmt.Errorf("PAC key etype=%d (want AES)", key.KeyType)
	}
	serverSum, err := et.GetChecksumHash(key.KeyValue, raw, uint32(keyusage.KERB_NON_KERB_CKSUM_SALT))
	if err != nil {
		return nil, err
	}
	if len(serverSum) < 12 {
		return nil, fmt.Errorf("checksum len %d", len(serverSum))
	}
	copy(raw[bufs[2].off+4:bufs[2].off+16], serverSum[:12])
	kdcSum, err := et.GetChecksumHash(key.KeyValue, raw[bufs[2].off+4:bufs[2].off+16], uint32(keyusage.KERB_NON_KERB_CKSUM_SALT))
	if err != nil {
		return nil, err
	}
	copy(raw[bufs[3].off+4:bufs[3].off+16], kdcSum[:12])
	return raw, nil
}

type pacBuf struct {
	typ  uint32
	data []byte
	off  int
}

func packPAC(bufs []pacBuf) []byte {
	hdr := 8 + 16*len(bufs)
	off := hdr
	for i := range bufs {
		for off%8 != 0 {
			off++
		}
		bufs[i].off = off
		off += len(bufs[i].data)
	}
	out := make([]byte, off)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(bufs)))
	binary.LittleEndian.PutUint32(out[4:8], pacVersion)
	for i, b := range bufs {
		p := 8 + i*16
		binary.LittleEndian.PutUint32(out[p:p+4], b.typ)
		binary.LittleEndian.PutUint32(out[p+4:p+8], uint32(len(b.data)))
		binary.LittleEndian.PutUint64(out[p+8:p+16], uint64(b.off))
		copy(out[b.off:], b.data)
	}
	return out
}

func marshalClientInfo(name string, t time.Time) []byte {
	u := utf16.Encode([]rune(name))
	b := make([]byte, 8+2+len(u)*2)
	ft := unixToFiletime64(t)
	binary.LittleEndian.PutUint64(b[0:8], ft)
	binary.LittleEndian.PutUint16(b[8:10], uint16(len(u)*2))
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[10+i*2:], r)
	}
	return b
}

func unixToFiletime64(t time.Time) uint64 {
	const epochDiff uint64 = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

func marshalLogonInfo(u PACUser) ([]byte, error) {
	sid, err := encodeRPCSID(u.DomainSID)
	if err != nil {
		return nil, err
	}
	nb := netbiosDomain(u.Domain)
	n := ndrWriter{ref: 0x00020000}
	ft := unixToFiletime64(u.AuthTime)
	for i := 0; i < 6; i++ {
		if i == 0 {
			n.u64(ft)
		} else {
			n.u64(neverTime)
		}
	}
	n.rpcUnicode(u.User) // EffectiveName
	n.rpcUnicode("")     // FullName
	n.rpcUnicode("")
	n.rpcUnicode("")
	n.rpcUnicode("")
	n.rpcUnicode("")
	n.u16(1) // LogonCount
	n.u16(0)
	n.u32(u.RID)
	n.u32(513) // PrimaryGroupID Domain Users
	n.u32(uint32(len(u.Groups)))
	n.ptr()   // GroupIDs
	n.u32(0)  // UserFlags
	n.pad(16) // UserSessionKey
	n.rpcUnicode("")
	n.rpcUnicode(nb)
	n.ptr() // LogonDomainID
	n.u32(0)
	n.u32(0)
	n.u32(uacNormalDontExpire)
	n.u32(0) // SubAuthStatus
	n.u64(0)
	n.u64(0)
	n.u32(0)
	n.u32(0)
	n.u32(0) // SIDCount
	n.u32(0) // ExtraSids null
	n.u32(0) // ResourceGroupDomainSID null
	n.u32(0)
	n.u32(0) // ResourceGroupIDs null

	// deferred EffectiveName … HomeDirectoryDrive
	n.conformantString(u.User)
	n.conformantString("")
	n.conformantString("")
	n.conformantString("")
	n.conformantString("")
	n.conformantString("")
	// GroupIDs
	n.u32(uint32(len(u.Groups)))
	for _, g := range u.Groups {
		n.u32(g)
		n.u32(groupAttrDefault)
	}
	n.conformantString("")
	n.conformantString(nb)
	n.bytes(sid)
	return n.buf, nil
}

func netbiosDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if i := strings.Index(domain, "."); i > 0 {
		return strings.ToUpper(domain[:i])
	}
	return strings.ToUpper(domain)
}

func encodeRPCSID(s string) ([]byte, error) {
	raw, err := encodeSIDBytes(s)
	if err != nil {
		return nil, err
	}
	// NDR SID: revision, subcount, authority[6], subauths[] — already that layout from EncodeSID.
	return raw, nil
}

func encodeSIDBytes(s string) ([]byte, error) {
	// inline to avoid ldapcli import cycle
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToUpper(s), "S-") {
		return nil, fmt.Errorf("sid %q", s)
	}
	parts := strings.Split(s[2:], "-")
	if len(parts) < 3 {
		return nil, fmt.Errorf("sid %q", s)
	}
	rev, err := parseU(parts[0], 8)
	if err != nil {
		return nil, err
	}
	ia, err := parseU(parts[1], 48)
	if err != nil {
		return nil, err
	}
	subs := parts[2:]
	out := make([]byte, 8+4*len(subs))
	out[0] = byte(rev)
	out[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		out[2+i] = byte(ia >> uint(8*(5-i)))
	}
	for i, p := range subs {
		n, err := parseU(p, 32)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(out[8+4*i:], uint32(n))
	}
	return out, nil
}

func parseU(s string, bits int) (uint64, error) {
	var n uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number %q", s)
		}
		n = n*10 + uint64(c-'0')
	}
	if bits < 64 && n > (1<<uint(bits))-1 {
		return 0, fmt.Errorf("overflow %s", s)
	}
	return n, nil
}

type ndrWriter struct {
	buf []byte
	ref uint32
}

func (n *ndrWriter) u16(v uint16) {
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], v)
	n.buf = append(n.buf, t[:]...)
}
func (n *ndrWriter) u32(v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	n.buf = append(n.buf, t[:]...)
}
func (n *ndrWriter) u64(v uint64) {
	var t [8]byte
	binary.LittleEndian.PutUint64(t[:], v)
	n.buf = append(n.buf, t[:]...)
}
func (n *ndrWriter) pad(k int) {
	n.buf = append(n.buf, make([]byte, k)...)
}
func (n *ndrWriter) ptr() uint32 {
	n.ref += 4
	id := n.ref
	n.u32(id)
	return id
}
func (n *ndrWriter) rpcUnicode(s string) {
	u := utf16.Encode([]rune(s))
	nb := uint16(len(u) * 2)
	n.u16(nb)
	n.u16(nb + 2)
	n.ptr()
}
func (n *ndrWriter) conformantString(s string) {
	u := utf16.Encode([]rune(s))
	// include null
	u = append(u, 0)
	n.align4()
	n.u32(uint32(len(u)))
	n.u32(0)
	n.u32(uint32(len(u)))
	for _, r := range u {
		n.u16(r)
	}
	n.align4()
}
func (n *ndrWriter) bytes(b []byte) {
	n.align4()
	n.buf = append(n.buf, b...)
	n.align4()
}
func (n *ndrWriter) align4() {
	for len(n.buf)%4 != 0 {
		n.buf = append(n.buf, 0)
	}
}
