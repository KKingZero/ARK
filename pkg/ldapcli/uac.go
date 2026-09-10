package ldapcli

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// UACAccountDisable is ADS_UF_ACCOUNTDISABLE.
const UACAccountDisable uint32 = 0x0002

// ApplyAccountDisable sets or clears ACCOUNTDISABLE without touching other bits.
func ApplyAccountDisable(uac uint32, disable bool) uint32 {
	if disable {
		return uac | UACAccountDisable
	}
	return uac &^ UACAccountDisable
}

// SetAccountDisabled enables (disable=false) or disables a user by UAC bit.
func SetAccountDisabled(conn *ldap.Conn, baseDN, sam string, disable bool) (oldUAC, newUAC uint32, err error) {
	if conn == nil {
		return 0, 0, fmt.Errorf("ldap conn required")
	}
	sam = strings.TrimSpace(sam)
	if baseDN == "" || sam == "" {
		return 0, 0, fmt.Errorf("base DN and sAMAccountName required")
	}
	filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(sam))
	entries, err := Search(conn, baseDN, filter, []string{"distinguishedName", "sAMAccountName", "userAccountControl"})
	if err != nil {
		return 0, 0, err
	}
	if len(entries) == 0 {
		return 0, 0, fmt.Errorf("object %q not found", sam)
	}
	e := entries[0]
	raw := strings.TrimSpace(e.GetAttributeValue("userAccountControl"))
	if raw == "" {
		return 0, 0, fmt.Errorf("userAccountControl missing on %s", e.DN)
	}
	n, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("userAccountControl %q: %w", raw, err)
	}
	oldUAC = uint32(n)
	newUAC = ApplyAccountDisable(oldUAC, disable)
	if oldUAC == newUAC {
		return oldUAC, newUAC, nil
	}
	mod := ldap.NewModifyRequest(e.DN, nil)
	mod.Replace("userAccountControl", []string{fmt.Sprintf("%d", newUAC)})
	if err := conn.Modify(mod); err != nil {
		return oldUAC, newUAC, fmt.Errorf("ldap set userAccountControl on %s: %w", e.DN, err)
	}
	return oldUAC, newUAC, nil
}
