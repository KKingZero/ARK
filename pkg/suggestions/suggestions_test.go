package suggestions

import (
	"strings"
	"testing"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
)

func TestForLDAPEnumKerberoastable(t *testing.T) {
	actions := ForLDAPEnum(&pb.LDAPEnumResult{
		Domain:       "corp.local",
		Dc:           "dc01.corp.local",
		QueryType:    "kerberoastable",
		TotalResults: 2,
		Entries: []*pb.LDAPEntry{{
			Attributes: map[string]*pb.LDAPValues{
				"sAMAccountName":       {Values: []string{"svc_sql"}},
				"servicePrincipalName": {Values: []string{"MSSQLSvc/dc01.corp.local"}},
			},
		}},
	})
	if len(actions) == 0 {
		t.Fatal("expected actions")
	}
	if !strings.Contains(actions[0], "kerberoast") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForLDAPEnumInteresting(t *testing.T) {
	actions := ForLDAPEnum(&pb.LDAPEnumResult{
		Domain:       "support.htb",
		Dc:           "dc.support.htb",
		QueryType:    "interesting",
		TotalResults: 1,
		Entries: []*pb.LDAPEntry{
			{
				Dn: "CN=support,CN=Users,DC=support,DC=htb",
				Attributes: map[string]*pb.LDAPValues{
					"sAMAccountName": {Values: []string{"support"}},
					"info":           {Values: []string{"not-echoed-in-suggestion"}},
				},
			},
		},
	})
	if len(actions) == 0 {
		t.Fatal("expected suggestions")
	}
	joined := strings.Join(actions, " ")
	if !strings.Contains(joined, "lateral_move") && !strings.Contains(joined, "winrm") {
		t.Fatalf("expected winrm/lateral suggestion: %v", actions)
	}
	if strings.Contains(joined, "not-echoed") {
		t.Fatal("must not echo free-text secret into suggestions")
	}
}

func TestForSMBListShares(t *testing.T) {
	actions := ForSMB(&pb.SMBClientResult{
		Action: "list_shares",
		Host:   "10.1.1.1",
		Names:  []string{"ADMIN$", "support-tools", "IPC$"},
	})
	if len(actions) == 0 {
		t.Fatal("expected suggestions")
	}
	joined := strings.Join(actions, " ")
	if !strings.Contains(joined, "support-tools") {
		t.Fatalf("expected support-tools list_dir: %v", actions)
	}
}

func TestForLDAPEnumRBCDAndShadow(t *testing.T) {
	rbcd := ForLDAPEnum(&pb.LDAPEnumResult{
		QueryType:    "rbcd",
		TotalResults: 1,
		Entries: []*pb.LDAPEntry{{
			Attributes: map[string]*pb.LDAPValues{
				"sAMAccountName": {Values: []string{"DC$"}},
			},
		}},
	})
	joined := strings.Join(rbcd, " ")
	if !strings.Contains(joined, "DC$") || strings.Contains(joined, "rbcd write") {
		t.Fatalf("rbcd: %v", rbcd)
	}
	if strings.Contains(joined, "cifs/DC$") {
		t.Fatalf("dead SPN: %v", rbcd)
	}
	if !strings.Contains(joined, "cifs/<fqdn>") {
		t.Fatalf("want fqdn placeholder: %v", rbcd)
	}
	named := ForLDAPEnum(&pb.LDAPEnumResult{
		QueryType:    "rbcd",
		TotalResults: 1,
		Entries: []*pb.LDAPEntry{{
			Attributes: map[string]*pb.LDAPValues{
				"sAMAccountName": {Values: []string{"DC$"}},
				"dNSHostName":    {Values: []string{"dc.corp.local"}},
			},
		}},
	})
	if !strings.Contains(strings.Join(named, " "), "cifs/dc.corp.local") {
		t.Fatalf("want fqdn spn: %v", named)
	}
	sh := ForLDAPEnum(&pb.LDAPEnumResult{
		QueryType:    "shadow",
		TotalResults: 1,
		Entries: []*pb.LDAPEntry{{
			Attributes: map[string]*pb.LDAPValues{
				"sAMAccountName": {Values: []string{"admin"}},
			},
		}},
	})
	joined = strings.Join(sh, " ")
	if !strings.Contains(joined, "admin") || strings.Contains(joined, "ad shadow write") {
		t.Fatalf("shadow: %v", sh)
	}
}

func TestForACLVerbs(t *testing.T) {
	actions := ForACL(&pb.LDAPEnumResult{
		QueryType:    "acl",
		TotalResults: 2,
		Entries: []*pb.LDAPEntry{
			{
				Attributes: map[string]*pb.LDAPValues{
					"sAMAccountName": {Values: []string{"jake.h"}},
					"objectCategory": {Values: []string{"user"}},
					"rights":         {Values: []string{"ForceChangePassword"}},
				},
			},
			{
				Attributes: map[string]*pb.LDAPValues{
					"sAMAccountName": {Values: []string{"DC$"}},
					"objectCategory": {Values: []string{"computer"}},
					"rights":         {Values: []string{"GenericAll"}},
				},
			},
		},
	})
	joined := strings.Join(actions, "\n")
	if !strings.Contains(joined, "ad password --target jake.h") {
		t.Fatalf("want password verb: %v", actions)
	}
	if !strings.Contains(joined, "rbcd write --to DC$") {
		t.Fatalf("want rbcd verb: %v", actions)
	}
	if strings.Contains(joined, "BloodHound") || strings.Contains(joined, "review ") {
		t.Fatalf("must name a verb: %v", actions)
	}
	spn := ForACL(&pb.LDAPEnumResult{
		QueryType:    "acl",
		TotalResults: 1,
		Entries: []*pb.LDAPEntry{{
			Attributes: map[string]*pb.LDAPValues{
				"sAMAccountName": {Values: []string{"DC01$"}},
				"objectCategory": {Values: []string{"computer"}},
				"rights":         {Values: []string{"WriteSPN"}},
			},
		}},
	})
	if !strings.Contains(strings.Join(spn, "\n"), "servicePrincipalName") {
		t.Fatalf("want SPN set: %v", spn)
	}
}

func TestForACLEmpty(t *testing.T) {
	actions := ForACL(&pb.LDAPEnumResult{QueryType: "acl"})
	joined := strings.Join(actions, " ")
	if !strings.Contains(joined, "interesting") {
		t.Fatalf("%v", actions)
	}
}

func TestForLDAPEnumEmpty(t *testing.T) {
	actions := ForLDAPEnum(&pb.LDAPEnumResult{
		QueryType:    "kerberoastable",
		TotalResults: 0,
	})
	if len(actions) == 0 || !strings.Contains(actions[0], "asrep") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForKerberoast(t *testing.T) {
	actions := ForKerberoast(&pb.KerberoastResult{
		Hashes: []*pb.KerberoastHash{{SamAccountName: "svc"}},
	})
	if !strings.Contains(actions[0], "hashcat") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForCredDumpNTLM(t *testing.T) {
	actions := ForCredDump(&pb.CredDumpResult{
		Credentials: []*pb.Credential{{Type: "ntlm", Username: "admin"}},
	})
	if len(actions) == 0 || !strings.Contains(actions[0], "lateral_move") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestForPortscan(t *testing.T) {
	actions := ForPortscan(&pb.NetPortscanResult{
		Ports: []*pb.PortResult{{Host: "10.0.0.5", Port: 445, Open: true}},
	})
	if len(actions) == 0 || !strings.Contains(actions[0], "lateral_move") {
		t.Fatalf("unexpected actions: %v", actions)
	}
}

func TestCap(t *testing.T) {
	in := []string{"a", "b", "c", "d", "e", "f"}
	out := Cap(in)
	if len(out) != maxActions {
		t.Fatalf("cap len %d want %d", len(out), maxActions)
	}
}
