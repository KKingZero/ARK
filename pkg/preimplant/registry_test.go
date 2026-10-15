package preimplant

import "testing"

func TestHostCommandRegistry(t *testing.T) {
	for _, name := range []string{"ldap", "smb", "ad", "kerberos", "inbound", "winrm", "psexec", "mssql"} {
		if !IsHostCommand(name) {
			t.Fatalf("missing host command %s", name)
		}
	}
	if IsHostCommand("shell") {
		t.Fatal("implant command registered as host command")
	}
}
