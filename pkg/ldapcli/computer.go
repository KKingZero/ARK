package ldapcli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"

	"github.com/go-ldap/ldap/v3"
)

const uacWorkstation = 4096

// AddComputer creates a machine account when MAQ allows it.
// name is the CN / sAM without a trailing $ (one is added).
func AddComputer(conn *ldap.Conn, baseDN, name, password string) (sam string, err error) {
	if conn == nil {
		return "", fmt.Errorf("ldap conn required")
	}
	if baseDN == "" {
		return "", fmt.Errorf("base DN required")
	}
	name, err = SanitizeComputerName(name)
	if err != nil {
		return "", err
	}
	maq, ok, err := ReadMAQ(conn, baseDN)
	if err != nil {
		return "", err
	}
	if ok && maq <= 0 {
		return "", fmt.Errorf("ms-DS-MachineAccountQuota is %d — addcomputer refused", maq)
	}
	sam = name + "$"
	if password == "" {
		password, err = RandomMachinePassword()
		if err != nil {
			return "", err
		}
	}
	if strings.Contains(password, `"`) {
		return "", fmt.Errorf("password must not contain a double-quote")
	}
	ou := "CN=Computers," + baseDN
	dn := "CN=" + name + "," + ou
	const uacDisabledWorkstation = uacWorkstation | 2 // ACCOUNTDISABLE
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "user", "computer"})
	req.Attribute("sAMAccountName", []string{sam})
	req.Attribute("userAccountControl", []string{fmt.Sprintf("%d", uacDisabledWorkstation)})
	// unicodePwd cannot be set on Add (WILL_NOT_PERFORM). Do not set dNSHostName:
	// AD wants a FQDN, and RBCD/S4U only need the object.
	if err := conn.Add(req); err != nil {
		return "", fmt.Errorf("add computer %s: %w (need MAQ>0 + LDAPS)", dn, err)
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("unicodePwd", []string{string(EncodeUnicodePwd(password))})
	if err := conn.Modify(mod); err != nil {
		return sam, fmt.Errorf("set unicodePwd on %s: %w (object created; need LDAPS + complexity)", dn, err)
	}
	mod2 := ldap.NewModifyRequest(dn, nil)
	mod2.Replace("userAccountControl", []string{fmt.Sprintf("%d", uacWorkstation)})
	if err := conn.Modify(mod2); err != nil {
		return sam, fmt.Errorf("enable %s: %w (password set; account still disabled)", dn, err)
	}
	return sam, nil
}

// IsWillNotPerform is LDAP 53 / WILL_NOT_PERFORM (Pirate add-computer Add).
func IsWillNotPerform(err error) bool {
	if err == nil {
		return false
	}
	if ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "will_not_perform") || strings.Contains(s, "unwilling to perform")
}

// SanitizeComputerName is the CN / sAM prefix (no $).
func SanitizeComputerName(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, "$")
	if name == "" {
		return "", fmt.Errorf("computer name required")
	}
	if len(name) > 15 {
		return "", fmt.Errorf("computer name %q longer than 15 chars", name)
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' {
			continue
		}
		return "", fmt.Errorf("computer name %q has invalid rune %q", name, r)
	}
	return name, nil
}

// RandomMachinePassword returns a 20-byte hex secret (not a sAM prefix).
func RandomMachinePassword() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "ARK." + hex.EncodeToString(b[:]), nil
}
