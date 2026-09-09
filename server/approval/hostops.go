package approval

// HostOpRisk is the server-side allowlist for operator-host writes.
// Risk is never taken from the client.
var HostOpRisk = map[string]string{
	"host_ldap_set":                  "high",
	"host_ad_password":               "critical",
	"host_ad_add_computer":           "high",
	"host_rbcd_write":                "critical",
	"host_rbcd_clear":                "critical",
	"host_ad_shadow_auto":            "critical",
	"host_ad_shadow_clear":           "critical",
	"host_ad_dcsync":                 "critical",
	"host_kerberos_asktgt":           "high",
	"host_kerberos_s4u":              "critical",
	"host_kerberos_pkinit":           "critical",
	"host_kerberos_golden":           "critical",
	"host_kerberos_silver":           "critical",
	"host_ad_prp_clear_never_reveal": "critical",
	"host_ad_prp_add_reveal":         "critical",
}

// HostOpAllowed reports whether op is a known host write verb.
func HostOpAllowed(op string) (risk string, ok bool) {
	risk, ok = HostOpRisk[op]
	return risk, ok
}
