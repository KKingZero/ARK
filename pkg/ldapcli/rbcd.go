package ldapcli

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// AttrAllowedToAct is msDS-AllowedToActOnBehalfOfOtherIdentity.
const AttrAllowedToAct = "msDS-AllowedToActOnBehalfOfOtherIdentity"

// RightRBCD is the Impacket rbcd.py ACCESS_MASK (0x000F01FF).
const RightRBCD uint32 = 0x000F01FF

// RBCDState is the current AllowedToAct DACL on a computer.
type RBCDState struct {
	TargetDN   string
	TargetSAM  string
	Delegators []string // canonical SIDs allowed to act
}

// ReadRBCD returns who may act on toSAM (empty Delegators if the attr is unset).
func ReadRBCD(conn *ldap.Conn, baseDN, toSAM string) (RBCDState, error) {
	st := RBCDState{}
	e, err := lookupSAM(conn, baseDN, toSAM)
	if err != nil {
		return st, err
	}
	st.TargetDN = e.DN
	st.TargetSAM = e.GetAttributeValue("sAMAccountName")
	raw := e.GetRawAttributeValue(AttrAllowedToAct)
	if len(raw) == 0 {
		return st, nil
	}
	sids, err := ListAllowedToAct(raw)
	if err != nil {
		return st, fmt.Errorf("parse %s on %s: %w", AttrAllowedToAct, st.TargetDN, err)
	}
	st.Delegators = sids
	return st, nil
}

// WriteRBCD adds fromSAM's SID to toSAM's AllowedToAct DACL and reads back.
func WriteRBCD(conn *ldap.Conn, baseDN, toSAM, fromSAM string) (RBCDState, error) {
	if conn == nil {
		return RBCDState{}, fmt.Errorf("ldap conn required")
	}
	if strings.TrimSpace(fromSAM) == "" {
		return RBCDState{}, fmt.Errorf("--from required")
	}
	to, err := lookupSAM(conn, baseDN, toSAM)
	if err != nil {
		return RBCDState{}, fmt.Errorf("rbcd --to: %w", err)
	}
	if !entryIsComputer(to) {
		return RBCDState{}, fmt.Errorf("%s is not a computer", to.GetAttributeValue("sAMAccountName"))
	}
	if err := rejectDeniedAllowedToAct(to.GetRawAttributeValue(AttrAllowedToAct)); err != nil {
		return RBCDState{}, err
	}
	from, err := lookupSAM(conn, baseDN, fromSAM)
	if err != nil {
		return RBCDState{}, fmt.Errorf("rbcd --from: %w", err)
	}
	fromSID := from.GetRawAttributeValue("objectSid")
	if len(fromSID) == 0 {
		return RBCDState{}, fmt.Errorf("objectSid missing on %s", from.DN)
	}
	fromCanon, err := ParseSID(fromSID)
	if err != nil {
		return RBCDState{}, fmt.Errorf("from objectSid: %w", err)
	}
	existing := to.GetRawAttributeValue(AttrAllowedToAct)
	sids := []string{}
	if len(existing) > 0 {
		sids, err = ListAllowedToAct(existing)
		if err != nil {
			return RBCDState{}, fmt.Errorf("parse existing %s: %w", AttrAllowedToAct, err)
		}
	}
	if !containsSID(sids, fromCanon) {
		sids = append(sids, fromCanon)
	}
	owner := ownerSIDFromSD(existing)
	sd, err := BuildAllowedToActSD(owner, sids)
	if err != nil {
		return RBCDState{}, err
	}
	if err := replaceAllowedToAct(conn, to.DN, sd); err != nil {
		return RBCDState{}, err
	}
	st, err := ReadRBCD(conn, baseDN, to.GetAttributeValue("sAMAccountName"))
	if err != nil {
		return st, err
	}
	if !containsSID(st.Delegators, fromCanon) {
		return st, fmt.Errorf("rbcd write read-back missing %s on %s", fromCanon, st.TargetSAM)
	}
	return st, nil
}

// ClearRBCD removes fromSAM (or the whole attribute if fromSAM is empty) and reads back.
func ClearRBCD(conn *ldap.Conn, baseDN, toSAM, fromSAM string) (RBCDState, error) {
	if conn == nil {
		return RBCDState{}, fmt.Errorf("ldap conn required")
	}
	to, err := lookupSAM(conn, baseDN, toSAM)
	if err != nil {
		return RBCDState{}, fmt.Errorf("rbcd --to: %w", err)
	}
	if !entryIsComputer(to) {
		return RBCDState{}, fmt.Errorf("%s is not a computer", to.GetAttributeValue("sAMAccountName"))
	}
	if err := rejectDeniedAllowedToAct(to.GetRawAttributeValue(AttrAllowedToAct)); err != nil {
		return RBCDState{}, err
	}
	if strings.TrimSpace(fromSAM) == "" {
		if err := deleteAllowedToAct(conn, to.DN); err != nil {
			return RBCDState{}, err
		}
		return ReadRBCD(conn, baseDN, to.GetAttributeValue("sAMAccountName"))
	}
	from, err := lookupSAM(conn, baseDN, fromSAM)
	if err != nil {
		return RBCDState{}, fmt.Errorf("rbcd --from: %w", err)
	}
	fromCanon, err := ParseSID(from.GetRawAttributeValue("objectSid"))
	if err != nil {
		return RBCDState{}, fmt.Errorf("from objectSid: %w", err)
	}
	existing := to.GetRawAttributeValue(AttrAllowedToAct)
	sids := []string{}
	if len(existing) > 0 {
		sids, err = ListAllowedToAct(existing)
		if err != nil {
			return RBCDState{}, err
		}
	}
	kept := make([]string, 0, len(sids))
	for _, s := range sids {
		if !strings.EqualFold(s, fromCanon) {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		if err := deleteAllowedToAct(conn, to.DN); err != nil {
			return RBCDState{}, err
		}
		return ReadRBCD(conn, baseDN, to.GetAttributeValue("sAMAccountName"))
	}
	sd, err := BuildAllowedToActSD(ownerSIDFromSD(existing), kept)
	if err != nil {
		return RBCDState{}, err
	}
	if err := replaceAllowedToAct(conn, to.DN, sd); err != nil {
		return RBCDState{}, err
	}
	return ReadRBCD(conn, baseDN, to.GetAttributeValue("sAMAccountName"))
}

// ListAllowedToAct returns ACCESS_ALLOWED trustee SIDs from an AllowedToAct SD.
func ListAllowedToAct(sd []byte) ([]string, error) {
	if len(sd) == 0 {
		return nil, nil
	}
	if len(sd) < 20 {
		return nil, fmt.Errorf("sd too short (%d)", len(sd))
	}
	if sd[0] != 1 {
		return nil, fmt.Errorf("sd revision %d", sd[0])
	}
	ctrl := binaryU16(sd[2:4])
	if ctrl&seSelfRelative == 0 {
		return nil, fmt.Errorf("sd not self-relative")
	}
	if ctrl&seDACLPresent == 0 {
		return nil, nil
	}
	offDACL := binaryU32(sd[16:20])
	if offDACL == 0 || int(offDACL)+8 > len(sd) {
		return nil, fmt.Errorf("dacl offset")
	}
	return listDACLSIDs(sd, int(offDACL))
}

// BuildAllowedToActSD builds a self-relative SD allowing the given SIDs to act.
// owner may be empty; then BUILTIN\Administrators is used (Impacket default).
func BuildAllowedToActSD(owner []byte, trustees []string) ([]byte, error) {
	if len(owner) == 0 {
		var err error
		owner, err = EncodeSID("S-1-5-32-544")
		if err != nil {
			return nil, err
		}
	}
	var aces [][]byte
	for _, t := range trustees {
		sid, err := EncodeSID(t)
		if err != nil {
			return nil, err
		}
		aces = append(aces, allowedACEBytes(RightRBCD, sid))
	}
	return buildSelfRelativeSDBytes(owner, aces), nil
}

func listDACLSIDs(sd []byte, off int) ([]string, error) {
	aclSize := int(binaryU16(sd[off+2 : off+4]))
	aceCount := int(binaryU16(sd[off+4 : off+6]))
	if aclSize < 8 || off+aclSize > len(sd) {
		return nil, fmt.Errorf("acl size")
	}
	pos := off + 8
	end := off + aclSize
	var out []string
	for i := 0; i < aceCount && pos+8 <= end; i++ {
		aceType := sd[pos]
		aceSize := int(binaryU16(sd[pos+2 : pos+4]))
		if aceSize < 8 || pos+aceSize > end {
			break
		}
		if aceType == aceAllowed || aceType == aceAllowedObject {
			if sid, ok := trusteeSIDFromACE(sd[pos : pos+aceSize]); ok && !containsSID(out, sid) {
				out = append(out, sid)
			}
		}
		pos += aceSize
	}
	return out, nil
}

const (
	aceDenied       = 0x01
	aceDeniedObject = 0x06
)

func rejectDeniedAllowedToAct(sd []byte) error {
	if len(sd) < 20 || sd[0] != 1 {
		return nil
	}
	ctrl := binaryU16(sd[2:4])
	if ctrl&seSelfRelative == 0 || ctrl&seDACLPresent == 0 {
		return nil
	}
	off := int(binaryU32(sd[16:20]))
	if off == 0 || off+8 > len(sd) {
		return nil
	}
	aclSize := int(binaryU16(sd[off+2 : off+4]))
	aceCount := int(binaryU16(sd[off+4 : off+6]))
	if aclSize < 8 || off+aclSize > len(sd) {
		return nil
	}
	pos := off + 8
	end := off + aclSize
	for i := 0; i < aceCount && pos+8 <= end; i++ {
		aceType := sd[pos]
		aceSize := int(binaryU16(sd[pos+2 : pos+4]))
		if aceSize < 8 || pos+aceSize > end {
			break
		}
		if aceType == aceDenied || aceType == aceDeniedObject {
			return fmt.Errorf("AllowedToAct DACL has deny ACE; refuse to merge")
		}
		pos += aceSize
	}
	return nil
}

func trusteeSIDFromACE(ace []byte) (string, bool) {
	if len(ace) < 8+8 {
		return "", false
	}
	sidOff := 8
	if ace[0] == aceAllowedObject || ace[0] == aceDeniedObject {
		if len(ace) < 12 {
			return "", false
		}
		flags := binaryU32(ace[8:12])
		sidOff = 12
		if flags&objectTypePresent != 0 {
			sidOff += 16
		}
		if flags&0x00000002 != 0 {
			sidOff += 16
		}
	}
	if sidOff+8 > len(ace) {
		return "", false
	}
	sid, _, err := parseSID(ace, sidOff)
	if err != nil {
		return "", false
	}
	return sid, true
}

func entryIsComputer(e *ldap.Entry) bool {
	if e == nil {
		return false
	}
	for _, c := range e.GetAttributeValues("objectClass") {
		if strings.EqualFold(c, "computer") {
			return true
		}
	}
	oc := strings.ToLower(e.GetAttributeValue("objectCategory"))
	return strings.Contains(oc, "computer")
}

func ownerSIDFromSD(sd []byte) []byte {
	if len(sd) < 20 || sd[0] != 1 {
		return nil
	}
	off := binaryU32(sd[4:8])
	if off == 0 || int(off)+8 > len(sd) {
		return nil
	}
	_, n, err := parseSID(sd, int(off))
	if err != nil {
		return nil
	}
	return append([]byte(nil), sd[int(off):int(off)+n]...)
}

func lookupSAM(conn *ldap.Conn, baseDN, sam string) (*ldap.Entry, error) {
	if conn == nil {
		return nil, fmt.Errorf("ldap conn required")
	}
	sam = strings.TrimSpace(sam)
	if baseDN == "" || sam == "" {
		return nil, fmt.Errorf("base DN and sAMAccountName required")
	}
	attrs := []string{"distinguishedName", "sAMAccountName", "objectSid", "objectClass", "objectCategory", AttrAllowedToAct}
	tried := map[string]bool{}
	candidates := samCandidates(sam)
	var lastMiss string
	for _, c := range candidates {
		if tried[c] {
			continue
		}
		tried[c] = true
		filter := fmt.Sprintf("(sAMAccountName=%s)", ldap.EscapeFilter(c))
		entries, err := Search(conn, baseDN, filter, attrs)
		if err != nil {
			return nil, err
		}
		if len(entries) > 0 {
			return entries[0], nil
		}
		lastMiss = c
	}
	return nil, fmt.Errorf("object %q not found", lastMiss)
}

func samCandidates(sam string) []string {
	sam = strings.TrimSpace(sam)
	if sam == "" {
		return nil
	}
	if strings.HasSuffix(sam, "$") {
		return []string{sam}
	}
	return []string{sam + "$", sam}
}

func replaceAllowedToAct(conn *ldap.Conn, dn string, sd []byte) error {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace(AttrAllowedToAct, []string{string(sd)})
	if err := conn.Modify(mod); err != nil {
		return fmt.Errorf("ldap replace %s on %s: %w", AttrAllowedToAct, dn, err)
	}
	return nil
}

func deleteAllowedToAct(conn *ldap.Conn, dn string) error {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete(AttrAllowedToAct, nil)
	if err := conn.Modify(mod); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchAttribute) {
			return nil
		}
		return fmt.Errorf("ldap delete %s on %s: %w", AttrAllowedToAct, dn, err)
	}
	return nil
}

func allowedACEBytes(mask uint32, sid []byte) []byte {
	ace := make([]byte, 8+len(sid))
	ace[0] = aceAllowed
	putU16(ace[2:4], uint16(len(ace)))
	putU32(ace[4:8], mask)
	copy(ace[8:], sid)
	return ace
}

func buildSelfRelativeSDBytes(owner []byte, aces [][]byte) []byte {
	const hdr = 20
	aclBody := 8
	for _, a := range aces {
		aclBody += len(a)
	}
	offDACL := hdr
	offOwner := hdr + aclBody
	sd := make([]byte, offOwner+len(owner))
	sd[0] = 1
	putU16(sd[2:4], seSelfRelative|seDACLPresent)
	putU32(sd[4:8], uint32(offOwner))
	putU32(sd[16:20], uint32(offDACL))
	sd[offDACL] = 4
	putU16(sd[offDACL+2:offDACL+4], uint16(aclBody))
	putU16(sd[offDACL+4:offDACL+6], uint16(len(aces)))
	p := offDACL + 8
	for _, a := range aces {
		copy(sd[p:], a)
		p += len(a)
	}
	copy(sd[offOwner:], owner)
	return sd
}

func containsSID(sids []string, want string) bool {
	for _, s := range sids {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func binaryU16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}

func binaryU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func putU16(b []byte, v uint16) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
}

func putU32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
