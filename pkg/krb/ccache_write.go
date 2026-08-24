package krb

import (
	"encoding/binary"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
)

// CCacheCred is one credential written into a MIT ccache v4 file.
type CCacheCred struct {
	ClientRealm string
	Client      []string
	ServerRealm string
	Server      []string
	KeyType     int32
	Key         []byte
	AuthTime    time.Time
	StartTime   time.Time
	EndTime     time.Time
	RenewTill   time.Time
	Flags       uint32
	Ticket      []byte
}

// WriteCCache builds a version-4 MIT credential cache (big-endian).
func WriteCCache(c CCacheCred) ([]byte, error) {
	var b []byte
	b = append(b, 0x05, 0x04)
	// header: 12 bytes after the length field — tag 1 (delta-time), 8 zero bytes
	hdr := make([]byte, 2+4+8)
	binary.BigEndian.PutUint16(hdr[0:2], 12)
	binary.BigEndian.PutUint16(hdr[2:4], 1)
	binary.BigEndian.PutUint16(hdr[4:6], 8)
	b = append(b, hdr...)
	// Default principal, then the credential's client + server principals.
	def := writePrincipal(nametype.KRB_NT_PRINCIPAL, c.ClientRealm, c.Client)
	b = append(b, def...)
	b = append(b, def...)
	b = append(b, writePrincipal(nametype.KRB_NT_SRV_INST, c.ServerRealm, c.Server)...)
	b = appendU16(b, uint16(c.KeyType))
	b = appendData(b, c.Key)
	b = appendTime(b, c.AuthTime)
	b = appendTime(b, c.StartTime)
	b = appendTime(b, c.EndTime)
	b = appendTime(b, c.RenewTill)
	b = append(b, 0) // is_skey
	b = appendU32(b, c.Flags)
	b = appendU32(b, 0) // address count
	b = appendU32(b, 0) // authdata count
	b = appendData(b, c.Ticket)
	b = appendData(b, nil) // second ticket
	return b, nil
}

func writePrincipal(nameType int32, realm string, parts []string) []byte {
	var b []byte
	b = appendU32(b, uint32(nameType))
	b = appendU32(b, uint32(len(parts)))
	b = appendData(b, []byte(realm))
	for _, p := range parts {
		b = appendData(b, []byte(p))
	}
	return b
}

func appendU16(b []byte, v uint16) []byte {
	var t [2]byte
	binary.BigEndian.PutUint16(t[:], v)
	return append(b, t[:]...)
}

func appendU32(b []byte, v uint32) []byte {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	return append(b, t[:]...)
}

func appendData(b []byte, p []byte) []byte {
	b = appendU32(b, uint32(len(p)))
	return append(b, p...)
}

func appendTime(b []byte, t time.Time) []byte {
	var sec uint32
	if !t.IsZero() {
		sec = uint32(t.UTC().Unix())
	}
	return appendU32(b, sec)
}

func bitStringUint32(b []byte) uint32 {
	var buf [4]byte
	copy(buf[:], b)
	return binary.BigEndian.Uint32(buf[:])
}
