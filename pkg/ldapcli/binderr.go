package ldapcli

import (
	"strings"
)

// ClassifyBindError maps an LDAP bind failure to a spray result token.
func ClassifyBindError(err error) string {
	if err == nil {
		return "success"
	}
	s := err.Error()
	if strings.Contains(s, "data 533") {
		return "disabled(533)"
	}
	if strings.Contains(s, "data 775") || strings.Contains(strings.ToLower(s), "locked") {
		return "locked"
	}
	if strings.Contains(s, "data 532") {
		return "expired"
	}
	return "invalid"
}
