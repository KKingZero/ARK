package ldapcli

import (
	"fmt"
	"strings"
)

// QueryFilters are the same named types as implant ldap-enum (host-side).
var QueryFilters = map[string]string{
	"kerberoastable":           "(&(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
	"asrep_roastable":          "(userAccountControl:1.2.840.113556.1.4.803:=4194304)",
	"computers":                "(objectCategory=computer)",
	"dcs":                      "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
	"gpos":                     "(objectClass=groupPolicyContainer)",
	"trusts":                   "(objectClass=trustedDomain)",
	"unconstrained_delegation": "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
	"constrained_delegation":   "(msDS-AllowedToDelegateTo=*)",
	"interesting":              "(&(objectCategory=person)(objectClass=user)(|(info=*)(description=*)(comment=*)))",
	"secrets":                  "(&(objectCategory=person)(objectClass=user)(|(info=*)(description=*)(comment=*)))",
	"users":                    "(&(objectCategory=person)(objectClass=user))",
	"groups":                   "(objectCategory=group)",
	"admins":                   "(&(objectCategory=person)(adminCount=1))",
	"rbcd":                     "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
}

// DefaultAttrs for each query type.
var DefaultAttrs = map[string][]string{
	"kerberoastable":           {"sAMAccountName", "servicePrincipalName", "distinguishedName", "memberOf"},
	"asrep_roastable":          {"sAMAccountName", "distinguishedName", "userAccountControl"},
	"computers":                {"dNSHostName", "operatingSystem", "operatingSystemVersion", "distinguishedName"},
	"dcs":                      {"dNSHostName", "operatingSystem", "distinguishedName"},
	"gpos":                     {"displayName", "gPCFileSysPath", "distinguishedName"},
	"trusts":                   {"cn", "trustDirection", "trustType", "trustAttributes"},
	"unconstrained_delegation": {"dNSHostName", "sAMAccountName", "distinguishedName"},
	"constrained_delegation":   {"dNSHostName", "sAMAccountName", "msDS-AllowedToDelegateTo", "distinguishedName"},
	"interesting":              {"sAMAccountName", "distinguishedName", "info", "description", "comment", "memberOf"},
	"secrets":                  {"sAMAccountName", "distinguishedName", "info", "description", "comment", "memberOf"},
	"users":                    {"sAMAccountName", "distinguishedName", "memberOf", "lastLogon", "info", "description"},
	"groups":                   {"sAMAccountName", "distinguishedName", "member"},
	"admins":                   {"sAMAccountName", "distinguishedName", "memberOf", "adminCount"},
	"domain_admins":            {"sAMAccountName", "distinguishedName", "memberOf", "adminCount"},
	"rbcd":                     {"sAMAccountName", "dNSHostName", "distinguishedName", "msDS-AllowedToActOnBehalfOfOtherIdentity"},
}

// FilterFor returns the LDAP filter for a named query type.
func FilterFor(queryType, baseDN string) (string, error) {
	if queryType == "domain_admins" {
		return "(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users," + baseDN + "))", nil
	}
	f, ok := QueryFilters[queryType]
	if !ok {
		return "", fmtUnknownQuery(queryType)
	}
	return f, nil
}

func fmtUnknownQuery(q string) error {
	keys := make([]string, 0, len(QueryFilters)+1)
	keys = append(keys, "domain_admins", "dangling")
	for k := range QueryFilters {
		keys = append(keys, k)
	}
	return fmt.Errorf("unknown query type %q (available: %s)", q, strings.Join(keys, ", "))
}
