package ldapcli

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// ESC1 / enrollment GUIDs (MS-ADTS / MS-WCCE).
const (
	GUIDCertificateEnrollment    = "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	GUIDCertificateAutoEnroll    = "a05b8cc2-17bc-4802-a710-e7c15ab866a2"
	EKUClientAuth                = "1.3.6.1.5.5.7.3.2"
	NameFlagEnrolleeSuppliesSubj = 1
	schemaV1                     = 1
	templateFlagsESC1            = 131680 // 0x20260 — publish + add-template-name, no User SD
	privateKeyFlagExportable     = 16842752
)

// TemplateDN is CN=<name>,CN=Certificate Templates,CN=Public Key Services,CN=Services,<configNC>.
func TemplateDN(configNC, name string) (string, error) {
	name = strings.TrimSpace(name)
	if configNC == "" || name == "" {
		return "", fmt.Errorf("config NC and template name required")
	}
	if strings.ContainsAny(name, `,*\+<>;"`) || strings.Contains(name, "/") {
		return "", fmt.Errorf("template name %q has LDAP specials", name)
	}
	return "CN=" + name + ",CN=Certificate Templates,CN=Public Key Services,CN=Services," + configNC, nil
}

// CreateESC1Template adds a schema-v1 ESC1 template (enrollee supplies subject + Client Auth).
// nTSecurityDescriptor is omitted so the creator owns the object (do not copy User).
func CreateESC1Template(conn *ldap.Conn, name string) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("ldap conn required")
	}
	cfgNC, err := RootDSEAttr(conn, "configurationNamingContext")
	if err != nil || cfgNC == "" {
		return "", fmt.Errorf("configurationNamingContext: %w", err)
	}
	dn, err := TemplateDN(cfgNC, name)
	if err != nil {
		return "", err
	}
	if _, err := GetTemplate(conn, name); err == nil {
		return "", fmt.Errorf("template %s already exists", name)
	}
	exp := durationFiletime(365 * 24 * time.Hour)
	overlap := durationFiletime(6 * 7 * 24 * time.Hour)
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "pKICertificateTemplate"})
	req.Attribute("cn", []string{name})
	req.Attribute("displayName", []string{name})
	req.Attribute("flags", []string{strconv.Itoa(templateFlagsESC1)})
	req.Attribute("revision", []string{"100"})
	req.Attribute("pKIDefaultKeySpec", []string{"1"})
	req.Attribute("pKIMaxIssuingDepth", []string{"0"})
	req.Attribute("pKICriticalExtensions", []string{"2.5.29.15", "2.5.29.17"})
	req.Attribute("pKIExtendedKeyUsage", []string{EKUClientAuth})
	req.Attribute("pKIKeyUsage", []string{string([]byte{0x86, 0x00})})
	req.Attribute("pKIExpirationPeriod", []string{string(exp)})
	req.Attribute("pKIOverlapPeriod", []string{string(overlap)})
	req.Attribute("msPKI-RA-Signature", []string{"0"})
	req.Attribute("msPKI-Enrollment-Flag", []string{"0"})
	req.Attribute("msPKI-Private-Key-Flag", []string{strconv.Itoa(privateKeyFlagExportable)})
	req.Attribute("msPKI-Certificate-Name-Flag", []string{strconv.Itoa(NameFlagEnrolleeSuppliesSubj)})
	req.Attribute("msPKI-Minimal-Key-Size", []string{"2048"})
	req.Attribute("msPKI-Template-Schema-Version", []string{strconv.Itoa(schemaV1)})
	req.Attribute("msPKI-Template-Minor-Revision", []string{"0"})
	if err := conn.Add(req); err != nil {
		return "", fmt.Errorf("add template %s: %w", dn, err)
	}
	return dn, nil
}

// GetTemplate returns the pKICertificateTemplate named cn.
func GetTemplate(conn *ldap.Conn, name string) (*ldap.Entry, error) {
	cfgNC, err := RootDSEAttr(conn, "configurationNamingContext")
	if err != nil {
		return nil, err
	}
	dn, err := TemplateDN(cfgNC, name)
	if err != nil {
		return nil, err
	}
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 15, false,
		"(objectClass=pKICertificateTemplate)",
		[]string{"cn", "displayName", "msPKI-Certificate-Name-Flag", "msPKI-Template-Schema-Version", "nTSecurityDescriptor", "flags"},
		[]ldap.Control{&ldap.ControlMicrosoftSDFlags{ControlValue: SDFlagsOwnerDACL, Criticality: true}},
	)
	sr, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("template %s not found", name)
	}
	return sr.Entries[0], nil
}

// DeleteTemplate removes the template object we created.
func DeleteTemplate(conn *ldap.Conn, name string) error {
	e, err := GetTemplate(conn, name)
	if err != nil {
		return err
	}
	if err := conn.Del(ldap.NewDelRequest(e.DN, nil)); err != nil {
		return fmt.Errorf("delete template %s: %w", e.DN, err)
	}
	return nil
}

// GrantTemplateEnroll writes Enroll + AutoEnroll + GenericAll for trusteeSAM (domain object).
func GrantTemplateEnroll(conn *ldap.Conn, domainBase, name, trusteeSAM string) error {
	if strings.TrimSpace(trusteeSAM) == "" {
		return fmt.Errorf("--trustee required")
	}
	tpl, err := GetTemplate(conn, name)
	if err != nil {
		return err
	}
	trustee, err := lookupSAM(conn, domainBase, trusteeSAM)
	if err != nil {
		return fmt.Errorf("trustee: %w", err)
	}
	sidRaw := trustee.GetRawAttributeValue("objectSid")
	if len(sidRaw) == 0 {
		return fmt.Errorf("objectSid missing on %s", trustee.DN)
	}
	sid, err := ParseSID(sidRaw)
	if err != nil {
		return err
	}
	owner := ownerSIDFromSD(tpl.GetRawAttributeValue("nTSecurityDescriptor"))
	if len(owner) == 0 {
		owner = append([]byte(nil), sidRaw...)
	}
	sd, err := BuildTemplateEnrollSD(owner, sid)
	if err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(tpl.DN, []ldap.Control{
		&ldap.ControlMicrosoftSDFlags{ControlValue: SDFlagsOwnerDACL, Criticality: true},
	})
	mod.Replace("nTSecurityDescriptor", []string{string(sd)})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("grant enroll on %s: %w", tpl.DN, err)
	}
	return nil
}

// BuildTemplateEnrollSD is Enroll + AutoEnroll object ACEs plus GenericAll.
func BuildTemplateEnrollSD(owner []byte, trusteeSID string) ([]byte, error) {
	sid, err := EncodeSID(trusteeSID)
	if err != nil {
		return nil, err
	}
	enroll, err := EncodeWindowsGUID(GUIDCertificateEnrollment)
	if err != nil {
		return nil, err
	}
	auto, err := EncodeWindowsGUID(GUIDCertificateAutoEnroll)
	if err != nil {
		return nil, err
	}
	aces := [][]byte{
		allowedObjectACEBytes(RightControlAccess, enroll, sid),
		allowedObjectACEBytes(RightControlAccess, auto, sid),
		allowedACEBytes(RightGenericAll|RightWriteDACL|RightWriteOwner, sid),
	}
	return buildSelfRelativeSDBytes(owner, aces), nil
}

func allowedObjectACEBytes(mask uint32, objectType, sid []byte) []byte {
	ace := make([]byte, 12+16+len(sid))
	ace[0] = aceAllowedObject
	putU16(ace[2:4], uint16(len(ace)))
	putU32(ace[4:8], mask)
	putU32(ace[8:12], objectTypePresent)
	copy(ace[12:28], objectType)
	copy(ace[28:], sid)
	return ace
}

// EncodeWindowsGUID encodes mixed-endian Windows GUID bytes (ACE ObjectType).
func EncodeWindowsGUID(s string) ([]byte, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.Trim(s, "{}")
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return nil, fmt.Errorf("guid %q", s)
	}
	d1, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return nil, err
	}
	d2, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, err
	}
	d3, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		return nil, err
	}
	rest := parts[3] + parts[4]
	rb, err := hex.DecodeString(rest)
	if err != nil || len(rb) != 8 {
		return nil, fmt.Errorf("guid tail %q", rest)
	}
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], uint32(d1))
	binary.LittleEndian.PutUint16(out[4:6], uint16(d2))
	binary.LittleEndian.PutUint16(out[6:8], uint16(d3))
	copy(out[8:], rb)
	return out, nil
}

func durationFiletime(d time.Duration) []byte {
	// Negative 100-ns intervals (FILETIME duration).
	n := -int64(d / 100)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(n))
	return b
}
