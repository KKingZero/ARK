package ldapcli

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	dnsTypeA      uint16 = 1
	dnsRankZone   byte   = 0xF0
	dnsVersion    byte   = 5
	defaultDNSTTL        = 180
)

// DNSZoneDN is the MicrosoftDNS zone container.
func DNSZoneDN(domain string, forest bool) (string, error) {
	base := BaseDN(domain)
	if base == "" {
		return "", fmt.Errorf("--domain required")
	}
	zone := strings.ToLower(strings.TrimSpace(domain))
	if forest {
		return "DC=_msdcs." + zone + ",CN=MicrosoftDNS,DC=ForestDnsZones," + base, nil
	}
	return "DC=" + zone + ",CN=MicrosoftDNS,DC=DomainDnsZones," + base, nil
}

// DNSNodeDN is DC=<relative>,<zoneDN>.
func DNSNodeDN(zoneDN, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, ",\\") {
		return "", fmt.Errorf("dns name required")
	}
	return "DC=" + name + "," + zoneDN, nil
}

// EncodeDNSRecordA builds an MS-DNSP DNS_RPC_RECORD A blob (Impacket/bloodyAD layout).
func EncodeDNSRecordA(ip net.IP, ttl uint32) ([]byte, error) {
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("A record requires IPv4")
	}
	if ttl == 0 {
		ttl = defaultDNSTTL
	}
	buf := make([]byte, 24+4)
	binary.LittleEndian.PutUint16(buf[0:2], 4)
	binary.LittleEndian.PutUint16(buf[2:4], dnsTypeA)
	buf[4] = dnsVersion
	buf[5] = dnsRankZone
	binary.BigEndian.PutUint32(buf[12:16], ttl)
	copy(buf[24:], v4)
	return buf, nil
}

// DecodeDNSRecordA reads type/IP/TTL from an A DNS_RPC_RECORD.
func DecodeDNSRecordA(blob []byte) (ip net.IP, ttl uint32, err error) {
	if len(blob) < 28 {
		return nil, 0, fmt.Errorf("dnsRecord too short (%d)", len(blob))
	}
	if binary.LittleEndian.Uint16(blob[2:4]) != dnsTypeA {
		return nil, 0, fmt.Errorf("not an A record")
	}
	ttl = binary.BigEndian.Uint32(blob[12:16])
	ip = net.IPv4(blob[24], blob[25], blob[26], blob[27])
	return ip, ttl, nil
}

// AddDNSRecordA creates or replaces a dnsNode A record.
func AddDNSRecordA(conn *ldap.Conn, domain, name, ipStr string, forest bool) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("ldap conn required")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IPv4 %q", ipStr)
	}
	zone, err := DNSZoneDN(domain, forest)
	if err != nil {
		return "", err
	}
	dn, err := DNSNodeDN(zone, name)
	if err != nil {
		return "", err
	}
	blob, err := EncodeDNSRecordA(ip, defaultDNSTTL)
	if err != nil {
		return "", err
	}
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "dnsNode"})
	req.Attribute("dc", []string{name})
	req.Attribute("dnsRecord", []string{string(blob)})
	if err := conn.Add(req); err != nil {
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return dn, fmt.Errorf("dns add %s: %w", dn, err)
		}
		mod := ldap.NewModifyRequest(dn, nil)
		mod.Replace("dnsRecord", []string{string(blob)})
		if err := conn.Modify(mod); err != nil {
			return dn, fmt.Errorf("dns replace %s: %w", dn, err)
		}
	}
	return dn, nil
}

// DeleteDNSNode removes a dnsNode.
func DeleteDNSNode(conn *ldap.Conn, domain, name string, forest bool) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("ldap conn required")
	}
	zone, err := DNSZoneDN(domain, forest)
	if err != nil {
		return "", err
	}
	dn, err := DNSNodeDN(zone, name)
	if err != nil {
		return "", err
	}
	if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		return dn, fmt.Errorf("dns delete %s: %w", dn, err)
	}
	return dn, nil
}
