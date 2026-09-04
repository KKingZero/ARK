package adcs

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/KKingZero/ARK/pkg/smbcli"
)

// ICertRequestD (MS-WCCE)
var icertRequestDUUID = []byte{0x70, 0x6e, 0x9e, 0xd9, 0x88, 0xfc, 0xd0, 0x11, 0xb4, 0x98, 0x00, 0xa0, 0xc9, 0x03, 0x12, 0xf3}

const (
	icertRequestDVer   = 0
	icertRequestDOpReq = 3
	crInPKCS10         = 0x00000100
	crInDER            = 0x00000001
	crDispIssued       = 3
)

// RequestOptions is ICertRequestD::Request (one template, one CSR).
type RequestOptions struct {
	Host     string
	CA       string // pwszAuthority, e.g. danglingtree-CA
	Template string
	CSR      []byte
	Domain   string
	Username string
	Password string
	Hash     string
	Ticket   string
}

// RequestCert submits a PKCS#10 via SMB pipe cert (ICertRequestD).
func RequestCert(opts RequestOptions) ([]byte, error) {
	if opts.Host == "" || opts.CA == "" || len(opts.CSR) == 0 {
		return nil, fmt.Errorf("--host --ca and CSR required")
	}
	s, err := smbcli.Dial(smbcli.Options{
		Host:     opts.Host,
		Domain:   opts.Domain,
		Username: opts.Username,
		Password: opts.Password,
		Hash:     opts.Hash,
		Ticket:   opts.Ticket,
	})
	if err != nil {
		return nil, fmt.Errorf("smb for WCCE: %w", err)
	}
	defer s.Close()
	attribs := ""
	if opts.Template != "" {
		attribs = "CertificateTemplate:" + opts.Template + "\n"
	}
	bind := dcerpcBind(1, icertRequestDUUID, icertRequestDVer)
	ack, err := s.PipeTransceive("cert", bind)
	if err != nil {
		return nil, fmt.Errorf("cert pipe bind: %w", err)
	}
	if len(ack) < 3 || ack[2] != 12 {
		return nil, fmt.Errorf("cert pipe bind ack type=%d (want 12)", bAt(ack, 2))
	}
	req := encodeICertRequest(2, opts.CA, attribs, opts.CSR)
	resp, err := s.PipeTransceive("cert", req)
	if err != nil {
		return nil, fmt.Errorf("ICertRequestD.Request: %w", err)
	}
	cert, disp, err := parseICertRequestResp(resp)
	if err != nil {
		return nil, err
	}
	if disp != crDispIssued {
		return nil, fmt.Errorf("CA disposition=%d (want issued=3)", disp)
	}
	if len(cert) < 32 {
		return nil, fmt.Errorf("issued cert short (%d)", len(cert))
	}
	return cert, nil
}

func dcerpcBind(callID uint32, iface []byte, ver uint16) []byte {
	b := make([]byte, 72)
	b[0], b[1], b[2], b[3] = 5, 0, 11, 0x03
	b[4] = 0x10
	binary.LittleEndian.PutUint16(b[8:10], 72)
	binary.LittleEndian.PutUint32(b[12:16], callID)
	binary.LittleEndian.PutUint16(b[16:18], 4280)
	binary.LittleEndian.PutUint16(b[18:20], 4280)
	binary.LittleEndian.PutUint32(b[24:28], 1)
	binary.LittleEndian.PutUint16(b[30:32], 1)
	copy(b[32:48], iface)
	binary.LittleEndian.PutUint16(b[48:50], ver)
	// NDR transfer syntax
	ndr := []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
	copy(b[52:68], ndr)
	binary.LittleEndian.PutUint32(b[68:72], 2)
	return b
}

func encodeICertRequest(callID uint32, authority, attribs string, csr []byte) []byte {
	stub := ndrBuf{}
	stub.uniqueWString(authority)
	stub.u32(crInPKCS10 | crInDER)
	stub.u32(0) // pwszSerialNumber null
	stub.blob(attribsUTF16(attribs))
	stub.blob(csr)
	body := stub.b
	hdr := make([]byte, 24)
	hdr[0], hdr[1], hdr[2], hdr[3] = 5, 0, 0, 0x03
	hdr[4] = 0x10
	binary.LittleEndian.PutUint16(hdr[8:10], uint16(24+len(body)))
	binary.LittleEndian.PutUint32(hdr[12:16], callID)
	binary.LittleEndian.PutUint32(hdr[16:20], uint32(len(body)))
	binary.LittleEndian.PutUint16(hdr[22:24], icertRequestDOpReq)
	return append(hdr, body...)
}

func attribsUTF16(s string) []byte {
	if s == "" {
		return nil
	}
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2+2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[i*2:], r)
	}
	return b
}

func parseICertRequestResp(resp []byte) (cert []byte, disp uint32, err error) {
	if len(resp) < 24 {
		return nil, 0, fmt.Errorf("WCCE resp short")
	}
	if resp[2] != 2 {
		return nil, 0, fmt.Errorf("WCCE ptype %d (want 2 response)", resp[2])
	}
	stub := resp[24:]
	// HRESULT (4) + pdwRequestId (4) + pdwDisposition (4) + then blobs...
	if len(stub) < 12 {
		return nil, 0, fmt.Errorf("WCCE stub short")
	}
	hresult := binary.LittleEndian.Uint32(stub[0:4])
	if hresult != 0 {
		return nil, 0, fmt.Errorf("ICertRequestD HRESULT=0x%08x", hresult)
	}
	disp = binary.LittleEndian.Uint32(stub[8:12])
	// Walk remaining NDR for the largest OCTET STRING that looks like a cert (30 82 …).
	cert = findDERCert(stub[12:])
	return cert, disp, nil
}

func findDERCert(b []byte) []byte {
	for i := 0; i+4 < len(b); i++ {
		if b[i] != 0x30 || b[i+1] != 0x82 {
			continue
		}
		n := int(b[i+2])<<8 | int(b[i+3])
		end := i + 4 + n
		if n > 64 && end <= len(b) {
			return b[i:end]
		}
	}
	return nil
}

type ndrBuf struct{ b []byte }

func (n *ndrBuf) u32(v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	n.b = append(n.b, t[:]...)
}
func (n *ndrBuf) align4() {
	for len(n.b)%4 != 0 {
		n.b = append(n.b, 0)
	}
}
func (n *ndrBuf) uniqueWString(s string) {
	n.align4()
	if s == "" {
		n.u32(0)
		return
	}
	n.u32(0x20000)
	u := utf16.Encode([]rune(s))
	u = append(u, 0)
	n.u32(uint32(len(u)))
	n.u32(0)
	n.u32(uint32(len(u)))
	for _, r := range u {
		var t [2]byte
		binary.LittleEndian.PutUint16(t[:], r)
		n.b = append(n.b, t[:]...)
	}
	n.align4()
}
func (n *ndrBuf) blob(p []byte) {
	n.align4()
	n.u32(uint32(len(p)))
	if len(p) == 0 {
		n.u32(0)
		return
	}
	n.u32(0x20004)
	n.u32(uint32(len(p)))
	n.b = append(n.b, p...)
	n.align4()
}

func bAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}
