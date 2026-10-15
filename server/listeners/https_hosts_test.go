package listeners

import "testing"

func TestListenerCertHostsSpecificBind(t *testing.T) {
	got := listenerCertHosts("10.1.2.3")
	if len(got) != 1 || got[0] != "10.1.2.3" {
		t.Fatalf("specific bind: %v", got)
	}
}

func TestListenerCertHostsWildcardIncludesLoopback(t *testing.T) {
	for _, bind := range []string{"", "0.0.0.0", "::"} {
		got := listenerCertHosts(bind)
		have := map[string]bool{}
		for _, h := range got {
			have[h] = true
		}
		if !have["localhost"] || !have["127.0.0.1"] {
			t.Fatalf("bind %q missing loopback SANs: %v", bind, got)
		}
	}
}
