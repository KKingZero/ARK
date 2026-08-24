package krb

import "fmt"

// RODCKvno is kvno = rodcNumber << 16 (MS-KILE KeyList / RODC TGT).
func RODCKvno(rodcNumber uint32) uint32 {
	return rodcNumber << 16
}

// KeyListOptions is the host KeyList MVP (AES RODC krbtgt key required).
type KeyListOptions struct {
	RODCNumber uint32
	AESKeyHex  string
	User       string
	Domain     string
	KDC        string
}

// ValidateKeyList refuses RC4 and missing fields. Forging is lab-only and
// requires a live KDC — this returns the kvno that will be used.
func ValidateKeyList(opts KeyListOptions) (kvno uint32, err error) {
	if opts.RODCNumber == 0 {
		return 0, fmt.Errorf("--rodc-no required")
	}
	if opts.User == "" || opts.Domain == "" || opts.KDC == "" {
		return 0, fmt.Errorf("--user --domain --dc required")
	}
	if len(opts.AESKeyHex) != 64 {
		return 0, fmt.Errorf("--aes-file must be 32-byte AES256 hex (RC4 not offered)")
	}
	return RODCKvno(opts.RODCNumber), nil
}
