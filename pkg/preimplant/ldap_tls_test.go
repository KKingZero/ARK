package preimplant

import "testing"

func TestLDAPOptsTLSFlags(t *testing.T) {
	o, err := ldapOpts(map[string]string{"dc": "dc.lab"})
	if err != nil {
		t.Fatal(err)
	}
	if o.InsecureSkipVerify || o.StrictTLS {
		t.Fatalf("default should verify then fall back: %+v", o)
	}

	o, err = ldapOpts(map[string]string{"dc": "dc.lab", "tls-verify": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.StrictTLS || o.InsecureSkipVerify {
		t.Fatalf("tls-verify: %+v", o)
	}

	o, err = ldapOpts(map[string]string{"dc": "dc.lab", "insecure": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if !o.InsecureSkipVerify || o.StrictTLS {
		t.Fatalf("insecure: %+v", o)
	}

	if _, err := ldapOpts(map[string]string{"dc": "dc.lab", "insecure": "1", "tls-verify": "1"}); err == nil {
		t.Fatal("both flags accepted")
	}
}
