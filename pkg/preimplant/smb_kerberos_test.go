package preimplant

import (
	"strings"
	"testing"

	"github.com/KKingZero/ARK/pkg/smbcli"
)

func TestParseFlagsKerberosDoesNotEatNext(t *testing.T) {
	f, bare := ParseFlags([]string{"--host", "10.1.2.3", "--kerberos", "--user", "alice"})
	if !flagBool(f, "kerberos") || f["host"] != "10.1.2.3" || f["user"] != "alice" {
		t.Fatalf("%v", f)
	}
	if len(bare) != 0 {
		t.Fatalf("bare %v", bare)
	}
}

func TestPlanKerberosSMBRefuses(t *testing.T) {
	base := smbcli.Options{Host: "10.1.2.3:445", Username: "alice", Password: "pw", Domain: "lab.htb"}
	if d, err := planKerberosSMB(base, false); err != nil || d.Ask != nil || d.ClearSecret {
		t.Fatalf("off: %+v %v", d, err)
	}
	cases := []smbcli.Options{
		{Host: "10.1.2.3", Password: "pw", Domain: "lab.htb"},
		{Host: "10.1.2.3", Username: "alice", Domain: "lab.htb"},
		{Host: "10.1.2.3", Username: "alice", Password: "pw"},
		{Host: "10.1.2.3", Username: "alice", Password: "pw", Hash: "aa", Domain: "lab.htb"},
	}
	for _, o := range cases {
		if _, err := planKerberosSMB(o, true); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
}

func TestPlanKerberosSMBAskAndTicket(t *testing.T) {
	o := smbcli.Options{
		Host: "10.1.2.3:445", Username: "alice", Password: "pw", Domain: "LAB.HTB",
	}
	d, err := planKerberosSMB(o, true)
	if err != nil || d.Ask == nil || !d.ClearSecret {
		t.Fatalf("%+v %v", d, err)
	}
	if d.Ask.KDC != "10.1.2.3" || d.Ask.Password != "pw" || d.Ask.Hash != "" || d.Ask.Username != "alice" {
		t.Fatalf("ask %+v", d.Ask)
	}

	o.Password = ""
	o.Hash = "8846f7eaee8fb117ad06bdd830b7586c"
	o.KDC = "10.9.9.9"
	d, err = planKerberosSMB(o, true)
	if err != nil || d.Ask == nil || d.Ask.Hash == "" || d.Ask.Password != "" || d.Ask.KDC != "10.9.9.9" {
		t.Fatalf("hash %+v %v", d.Ask, err)
	}

	o.Ticket = "abc"
	o.Password = "pw"
	d, err = planKerberosSMB(o, true)
	if err != nil || d.Ask != nil || !d.ClearSecret {
		t.Fatalf("ticket wins: %+v %v", d, err)
	}
}

func TestPlanKerberosSMBErrorText(t *testing.T) {
	_, err := planKerberosSMB(smbcli.Options{Host: "h"}, true)
	if err == nil || !strings.Contains(err.Error(), "--user") {
		t.Fatal(err)
	}
}
