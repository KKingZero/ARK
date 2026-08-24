package ldapcli

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// ParseSID decodes a binary SID at the start of buf.
func ParseSID(buf []byte) (string, error) {
	s, _, err := parseSID(buf, 0)
	return s, err
}

// EncodeSID serializes a canonical SID (S-R-I-sub…).
func EncodeSID(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "S-") && !strings.HasPrefix(s, "s-") {
		return nil, fmt.Errorf("sid %q: want S-R-I-…", s)
	}
	parts := strings.Split(s[2:], "-")
	if len(parts) < 3 {
		return nil, fmt.Errorf("sid %q: too few components", s)
	}
	rev, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("sid revision: %w", err)
	}
	ia, err := strconv.ParseUint(parts[1], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("sid identifier authority: %w", err)
	}
	subs := parts[2:]
	if len(subs) > 15 {
		return nil, fmt.Errorf("sid %q: too many subauthorities", s)
	}
	out := make([]byte, 8+4*len(subs))
	out[0] = byte(rev)
	out[1] = byte(len(subs))
	for i := 0; i < 6; i++ {
		out[2+i] = byte(ia >> uint(8*(5-i)))
	}
	for i, p := range subs {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sid subauthority %s: %w", p, err)
		}
		binary.LittleEndian.PutUint32(out[8+4*i:], uint32(n))
	}
	return out, nil
}
