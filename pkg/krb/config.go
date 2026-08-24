package krb

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
)

// Realm uppercases a DNS domain for Kerberos.
func Realm(domain string) string {
	return strings.ToUpper(strings.TrimSpace(domain))
}

// NewConfig builds an in-memory krb5.conf (AES first, no DNS KDC lookup).
// RC4 is omitted so Protected Users–style accounts fail closed instead of falling back.
func NewConfig(domain, kdc string) (*config.Config, error) {
	domain = strings.TrimSpace(domain)
	kdc = strings.TrimSpace(kdc)
	if domain == "" || kdc == "" {
		return nil, fmt.Errorf("domain and kdc required")
	}
	kdc = strings.TrimPrefix(strings.TrimPrefix(kdc, "ldaps://"), "ldap://")
	if host, _, err := splitHostOptionalPort(kdc); err == nil {
		kdc = host
	}
	realm := Realm(domain)
	raw := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  preferred_preauth_types = 18,17

[realms]
  %s = {
    kdc = %s:88
    admin_server = %s:749
  }

[domain_realm]
  .%s = %s
  %s = %s
`, realm, realm, kdc, kdc, strings.ToLower(domain), realm, strings.ToLower(domain), realm)
	return config.NewFromString(raw)
}

// WriteConfigFile writes krb5.conf for gokrb5/go-ldap GSSAPI helpers that want a path.
func WriteConfigFile(dir, domain, kdc string) (string, error) {
	if _, err := NewConfig(domain, kdc); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "krb5.conf")
	return p, writeKrb5Conf(p, domain, kdc)
}

func writeKrb5Conf(path, domain, kdc string) error {
	kdc = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(kdc), "ldaps://"), "ldap://")
	if h, _, err := splitHostOptionalPort(kdc); err == nil {
		kdc = h
	}
	realm := Realm(domain)
	body := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = false
  dns_lookup_kdc = false
  default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
  permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
  %s = {
    kdc = %s:88
    admin_server = %s:749
  }
`, realm, realm, kdc, kdc)
	return os.WriteFile(path, []byte(body), 0o600)
}

func splitHostOptionalPort(host string) (string, string, error) {
	// net.SplitHostPort fails on bare host; treat as host-only.
	if strings.Count(host, ":") == 1 && !strings.HasPrefix(host, "[") {
		i := strings.LastIndex(host, ":")
		return host[:i], host[i+1:], nil
	}
	return host, "", nil
}
