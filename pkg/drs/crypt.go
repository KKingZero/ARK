package drs

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// DecryptAttributeValue is Impacket/MS-DRSR: MD5(sessionKey||salt16) → RC4, CRC32 prefix.
func DecryptAttributeValue(sessionKey, encrypted []byte) ([]byte, error) {
	if len(sessionKey) == 0 {
		return nil, fmt.Errorf("dcsync session key required")
	}
	if len(encrypted) < 20 {
		return nil, fmt.Errorf("encrypted attr short (%d)", len(encrypted))
	}
	salt, data := encrypted[:16], encrypted[16:]
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	c := newRC4(h.Sum(nil))
	plain := make([]byte, len(data))
	c.XORKeyStream(plain, data)
	if len(plain) < 4 {
		return nil, fmt.Errorf("dcsync plaintext short")
	}
	want := binary.LittleEndian.Uint32(plain[:4])
	payload := plain[4:]
	if crc32.ChecksumIEEE(payload) != want {
		return nil, fmt.Errorf("dcsync CRC32 mismatch")
	}
	return payload, nil
}

// EncryptAttributeValue is the inverse (tests).
func EncryptAttributeValue(sessionKey, payload []byte) ([]byte, error) {
	if len(sessionKey) == 0 {
		return nil, fmt.Errorf("session key required")
	}
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	sum := crc32.ChecksumIEEE(payload)
	plain := make([]byte, 4+len(payload))
	binary.LittleEndian.PutUint32(plain[:4], sum)
	copy(plain[4:], payload)
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	c := newRC4(h.Sum(nil))
	enc := make([]byte, len(plain))
	c.XORKeyStream(enc, plain)
	return append(salt, enc...), nil
}
