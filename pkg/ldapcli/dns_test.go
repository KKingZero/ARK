package ldapcli

import (
	"net"
	"testing"
)

func TestDNSZoneDN(t *testing.T) {
	d, err := DNSZoneDN("scaffold.htb", false)
	if err != nil || d != "DC=scaffold.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=scaffold,DC=htb" {
		t.Fatalf("domain %s %v", d, err)
	}
	f, err := DNSZoneDN("scaffold.htb", true)
	if err != nil || f != "DC=_msdcs.scaffold.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=scaffold,DC=htb" {
		t.Fatalf("forest %s %v", f, err)
	}
}

func TestEncodeDecodeDNSRecordA(t *testing.T) {
	ip := net.ParseIP("10.10.15.135")
	blob, err := EncodeDNSRecordA(ip, 180)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != 28 {
		t.Fatalf("len %d", len(blob))
	}
	got, ttl, err := DecodeDNSRecordA(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(ip) || ttl != 180 {
		t.Fatalf("ip %s ttl %d", got, ttl)
	}
}

func TestAddDNSRecordANilConn(t *testing.T) {
	if _, err := AddDNSRecordA(nil, "a.htb", "testdns", "10.1.2.3", false); err == nil {
		t.Fatal("nil")
	}
}
