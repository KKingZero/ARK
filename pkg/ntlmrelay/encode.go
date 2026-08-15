package ntlmrelay

import (
	"strings"
)

// percentEncodeAll matches Python urllib.parse.quote(s, safe=""):
// every byte except alphanumerics is %XX-encoded (uppercase hex).
// Dots and backslashes are encoded (required for Ghostlink LFI).
func percentEncodeAll(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&0xf])
	}
	return b.String()
}

// DoubleEncodePath percent-encodes path twice for IIS double-decode LFI
// (Ghostlink /api/download/{hash}: quote(quote(path, safe=""), safe="")).
func DoubleEncodePath(path string) string {
	return percentEncodeAll(percentEncodeAll(path))
}

// JoinDownloadAPI builds /api/download/<double-encoded-path> style URL path.
func JoinDownloadAPI(basePath, filePath string, doubleEncode bool) string {
	basePath = strings.TrimRight(basePath, "/")
	if basePath == "" {
		basePath = "/api/download"
	}
	p := filePath
	if doubleEncode {
		p = DoubleEncodePath(filePath)
	} else {
		p = percentEncodeAll(filePath)
	}
	return basePath + "/" + p
}
