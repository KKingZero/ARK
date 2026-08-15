package ldapcli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// DanglingResult is CA-published template names that have no AD object.
type DanglingResult struct {
	ConfigNC  string
	CA        []string // enrollment service CNs
	Published []string
	Existing  []string
	Missing   []string // published minus existing (the dangling names)
}

// DanglingTemplates diffs Enrollment Services certificateTemplates vs
// objects under CN=Certificate Templates.
func DanglingTemplates(conn *ldap.Conn) (*DanglingResult, error) {
	cfgNC, err := RootDSEAttr(conn, "configurationNamingContext")
	if err != nil || cfgNC == "" {
		return nil, fmt.Errorf("configurationNamingContext: %w", err)
	}
	out := &DanglingResult{ConfigNC: cfgNC}

	pki := "CN=Public Key Services,CN=Services," + cfgNC
	enrollBase := "CN=Enrollment Services," + pki
	entries, err := Search(conn, enrollBase, "(objectClass=pKIEnrollmentService)", []string{"cn", "certificateTemplates"})
	if err != nil {
		return nil, fmt.Errorf("enrollment services: %w", err)
	}
	pubSet := map[string]struct{}{}
	for _, e := range entries {
		out.CA = append(out.CA, e.GetAttributeValue("cn"))
		for _, t := range e.GetAttributeValues("certificateTemplates") {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			pubSet[t] = struct{}{}
		}
	}

	tplBase := "CN=Certificate Templates," + pki
	tpls, err := Search(conn, tplBase, "(objectClass=pKICertificateTemplate)", []string{"cn", "name", "displayName"})
	if err != nil {
		return nil, fmt.Errorf("certificate templates: %w", err)
	}
	existSet := map[string]struct{}{}
	for _, e := range tpls {
		cn := e.GetAttributeValue("cn")
		if cn == "" {
			cn = e.GetAttributeValue("name")
		}
		if cn != "" {
			existSet[cn] = struct{}{}
		}
	}

	for n := range pubSet {
		out.Published = append(out.Published, n)
	}
	for n := range existSet {
		out.Existing = append(out.Existing, n)
	}
	sort.Strings(out.Published)
	sort.Strings(out.Existing)
	for _, n := range out.Published {
		if _, ok := existSet[n]; !ok {
			out.Missing = append(out.Missing, n)
		}
	}
	return out, nil
}
