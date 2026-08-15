package ntlmrelay

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// ParseType3Identity extracts domain\user from an NTLM Type 3 message (raw bytes).
func ParseType3Identity(msg []byte) (domain, user string, err error) {
	if len(msg) < 64 {
		return "", "", fmt.Errorf("ntlm type3 too short")
	}
	if string(msg[0:8]) != "NTLMSSP\x00" {
		return "", "", fmt.Errorf("not NTLMSSP")
	}
	if binary.LittleEndian.Uint32(msg[8:12]) != 3 {
		return "", "", fmt.Errorf("not type 3 message")
	}
	// Offsets per NTLM Type3 layout
	domain = readNTLMString(msg, 28)
	user = readNTLMString(msg, 36)
	return domain, user, nil
}

func readNTLMString(msg []byte, fieldOffset int) string {
	if fieldOffset+8 > len(msg) {
		return ""
	}
	length := int(binary.LittleEndian.Uint16(msg[fieldOffset : fieldOffset+2]))
	// maxLen at +2
	offset := int(binary.LittleEndian.Uint32(msg[fieldOffset+4 : fieldOffset+8]))
	if length == 0 || offset+length > len(msg) {
		return ""
	}
	raw := msg[offset : offset+length]
	// Prefer UTF-16LE if even length and looks like wide chars
	if length%2 == 0 && length >= 2 {
		u16 := make([]uint16, length/2)
		for i := 0; i < len(u16); i++ {
			u16[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
		}
		return string(utf16.Decode(u16))
	}
	return string(raw)
}

// DecodeNTLMAuthHeader parses "NTLM <b64>" or "Negotiate <b64>" Authorization header.
func DecodeNTLMAuthHeader(h string) ([]byte, error) {
	h = strings.TrimSpace(h)
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid auth header")
	}
	scheme := strings.ToLower(parts[0])
	if scheme != "ntlm" && scheme != "negotiate" {
		return nil, fmt.Errorf("unsupported scheme %q", parts[0])
	}
	return base64.StdEncoding.DecodeString(strings.TrimSpace(parts[1]))
}

// EncodeNTLMAuthHeader builds "NTLM <b64>".
func EncodeNTLMAuthHeader(msg []byte) string {
	return "NTLM " + base64.StdEncoding.EncodeToString(msg)
}

// NTLMMessageType returns 1, 2, or 3.
func NTLMMessageType(msg []byte) (uint32, error) {
	if len(msg) < 12 || string(msg[0:8]) != "NTLMSSP\x00" {
		return 0, fmt.Errorf("not NTLMSSP")
	}
	return binary.LittleEndian.Uint32(msg[8:12]), nil
}
