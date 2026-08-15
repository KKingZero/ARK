package ldapcli

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// ContainsSAMPrefix reports whether password includes the sAMAccountName
// (or the token before '.' / '_'). Windows complexity often rejects this
// (DanglingTree: JakeReset#… vs jake.h).
func ContainsSAMPrefix(sam, password string) bool {
	sam = strings.TrimSpace(sam)
	password = strings.TrimSpace(password)
	if sam == "" || password == "" {
		return false
	}
	p := strings.ToLower(password)
	s := strings.ToLower(sam)
	if strings.Contains(p, s) {
		return true
	}
	if i := strings.IndexAny(s, "._"); i > 1 {
		if strings.Contains(p, s[:i]) {
			return true
		}
	}
	return false
}

// EncodeUnicodePwd is the AD unicodePwd encoding: UTF-16LE of `"password"`.
func EncodeUnicodePwd(password string) []byte {
	quoted := `"` + password + `"`
	u16 := utf16.Encode([]rune(quoted))
	b := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

// SetPassword replaces unicodePwd on targetSAM (ForceChangePassword / reset).
// Requires LDAPS. Refuses passwords that contain the SAM prefix unless force.
func SetPassword(conn *ldap.Conn, baseDN, targetSAM, newPass string, force bool) error {
	targetSAM = strings.TrimSpace(targetSAM)
	if targetSAM == "" {
		return fmt.Errorf("target sAMAccountName required")
	}
	if newPass == "" {
		return fmt.Errorf("new password required")
	}
	if strings.Contains(newPass, `"`) {
		return fmt.Errorf("password must not contain a double-quote (unicodePwd quoted-UTF16 encoding)")
	}
	if !force && ContainsSAMPrefix(targetSAM, newPass) {
		return fmt.Errorf("password contains sAM prefix %q (domain complexity will reject it); pick another or pass --force", targetSAM)
	}

	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(targetSAM))
	entries, err := Search(conn, baseDN, filter, []string{"distinguishedName", "sAMAccountName"})
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return fmt.Errorf("user %q not found", targetSAM)
	}
	dn := entries[0].DN

	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(EncodeUnicodePwd(newPass))})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("unicodePwd replace on %s: %w (need LDAPS + ForceChangePassword/reset right; complexity/history also fail here)", dn, err)
	}
	return nil
}
