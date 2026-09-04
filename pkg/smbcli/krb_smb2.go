package smbcli

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf16"

	"github.com/jcmturner/gokrb5/v8/types"
)

const (
	smb2Protocol                 = "\xfeSMB"
	smb2HeaderSize               = 64
	smb2Negotiate                = 0
	smb2SessionSetup             = 1
	smb2Logoff                   = 2
	smb2TreeConnect              = 3
	smb2TreeDisconnect           = 4
	smb2Create                   = 5
	smb2Close                    = 6
	smb2Read                     = 8
	smb2Write                    = 9
	smb2Ioctl                    = 11
	smb2QueryDirectory           = 14
	smb2SigningEnabled           = 0x0001
	smb2FlagsSigned              = 0x00000008
	statusMoreProcessingRequired = 0xC0000016
	fileOpen                     = 1
	fileShareRead                = 0x1
	fileShareWrite               = 0x2
	fileShareDelete              = 0x4
	fileDirectoryFile            = 0x00000001
	fileNonDirectoryFile         = 0x00000040
	fileOpenReparsePoint         = 0x00200000
	fileGenericRead              = 0x80000000
	fileListDirectory            = 0x1
	fileReadData                 = 0x1
	fileReadAttributes           = 0x80
	fileReadEA                   = 0x8
	fileSynchronize              = 0x100000
	fileInfoFileDirectory        = 0x01
)

var smb2le = binary.LittleEndian

type krbSession struct {
	conn       net.Conn
	host       string
	sessionID  uint64
	msgID      uint64
	trees      map[string]uint32
	sessionKey []byte
}

func smb2KerberosSession(conn net.Conn, host string, token []byte, key types.EncryptionKey) (*krbSession, error) {
	s := &krbSession{
		conn:       conn,
		host:       host,
		trees:      map[string]uint32{},
		sessionKey: append([]byte(nil), key.KeyValue...),
	}
	if err := s.negotiate(); err != nil {
		return nil, err
	}
	if err := s.sessionSetup(token); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *krbSession) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *krbSession) negotiate() error {
	body := make([]byte, 36+2)
	smb2le.PutUint16(body[0:2], 36)
	smb2le.PutUint16(body[2:4], 1)
	smb2le.PutUint16(body[4:6], smb2SigningEnabled)
	smb2le.PutUint16(body[8:10], 0)
	smb2le.PutUint16(body[36:38], 0x0202)
	hdr, err := s.roundtrip(smb2Negotiate, 0, 0, body)
	if err != nil {
		return fmt.Errorf("smb negotiate: %w", err)
	}
	if statusOf(hdr) != 0 {
		return fmt.Errorf("smb negotiate status=0x%08x", statusOf(hdr))
	}
	return nil
}

func (s *krbSession) sessionSetup(token []byte) error {
	body := sessionSetupBody(token)
	hdr, payload, err := s.roundtripPayload(smb2SessionSetup, 0, 0, body)
	if err != nil {
		return fmt.Errorf("smb session setup: %w", err)
	}
	st := statusOf(hdr)
	s.sessionID = smb2le.Uint64(hdr[40:48])
	if st == 0 {
		return nil
	}
	if st != statusMoreProcessingRequired {
		return fmt.Errorf("smb session setup status=0x%08x", st)
	}
	_ = payload
	// Kerberos AP-REP is in the security buffer; a second setup with empty token completes many servers.
	body = sessionSetupBody(nil)
	hdr, _, err = s.roundtripPayload(smb2SessionSetup, s.sessionID, 0, body)
	if err != nil {
		return fmt.Errorf("smb session setup (2): %w", err)
	}
	if statusOf(hdr) != 0 {
		return fmt.Errorf("smb session setup (2) status=0x%08x", statusOf(hdr))
	}
	if sid := smb2le.Uint64(hdr[40:48]); sid != 0 {
		s.sessionID = sid
	}
	return nil
}

func sessionSetupBody(token []byte) []byte {
	body := make([]byte, 24+len(token))
	smb2le.PutUint16(body[0:2], 25)
	body[2] = 0
	body[3] = smb2SigningEnabled
	smb2le.PutUint32(body[4:8], 0)
	smb2le.PutUint32(body[8:12], 0)
	smb2le.PutUint16(body[12:14], smb2HeaderSize+24)
	smb2le.PutUint16(body[14:16], uint16(len(token)))
	copy(body[24:], token)
	return body
}

func (s *krbSession) tree(share string) (uint32, error) {
	share = strings.Trim(share, `\`)
	if id, ok := s.trees[strings.ToLower(share)]; ok {
		return id, nil
	}
	path := `\\` + s.host + `\` + share
	u := utf16le(path)
	body := make([]byte, 8+len(u))
	smb2le.PutUint16(body[0:2], 9)
	smb2le.PutUint16(body[4:6], smb2HeaderSize+8)
	smb2le.PutUint16(body[6:8], uint16(len(u)))
	copy(body[8:], u)
	hdr, _, err := s.roundtripPayload(smb2TreeConnect, s.sessionID, 0, body)
	if err != nil {
		return 0, fmt.Errorf("tree connect %s: %w", share, err)
	}
	if statusOf(hdr) != 0 {
		return 0, fmt.Errorf("tree connect %s status=0x%08x", share, statusOf(hdr))
	}
	id := smb2le.Uint32(hdr[36:40])
	s.trees[strings.ToLower(share)] = id
	return id, nil
}

func (s *krbSession) ListDir(share, p string) ([]string, error) {
	tid, err := s.tree(share)
	if err != nil {
		return nil, err
	}
	name := NormalizePath(p)
	if name == "." {
		name = ""
	}
	fid, err := s.create(tid, name, fileListDirectory|fileReadAttributes|fileSynchronize, fileDirectoryFile)
	if err != nil {
		return nil, err
	}
	defer s.closeFID(tid, fid)
	raw, err := s.queryDirectory(tid, fid)
	if err != nil {
		return nil, err
	}
	return parseDirInfo(raw), nil
}

func (s *krbSession) Download(share, p string) ([]byte, error) {
	tid, err := s.tree(share)
	if err != nil {
		return nil, err
	}
	fid, err := s.create(tid, NormalizePath(p), fileReadData|fileReadAttributes|fileReadEA|fileSynchronize, fileNonDirectoryFile)
	if err != nil {
		return nil, err
	}
	defer s.closeFID(tid, fid)
	return s.readAll(tid, fid)
}

func (s *krbSession) ListShares() ([]string, error) {
	tid, err := s.tree("IPC$")
	if err != nil {
		return nil, err
	}
	fid, err := s.create(tid, "srvsvc", fileReadData|fileReadAttributes|0x0002, fileNonDirectoryFile)
	if err != nil {
		return nil, fmt.Errorf("open srvsvc: %w", err)
	}
	defer s.closeFID(tid, fid)
	bind := srvsvcBind(1)
	if _, err := s.writeFID(tid, fid, bind); err != nil {
		return nil, err
	}
	ack, err := s.readFID(tid, fid, 4280)
	if err != nil {
		return nil, err
	}
	if len(ack) < 3 || ack[2] != 12 {
		return nil, fmt.Errorf("srvsvc bind ack type=%d", bAt(ack, 2))
	}
	req := netShareEnumAll(2, s.host)
	if _, err := s.writeFID(tid, fid, req); err != nil {
		return nil, err
	}
	resp, err := s.readFID(tid, fid, 0x10000)
	if err != nil {
		return nil, err
	}
	return parseNetShareEnum(resp)
}

func (s *krbSession) create(tid uint32, name string, access, options uint32) ([16]byte, error) {
	var zero [16]byte
	u := utf16le(strings.ReplaceAll(name, "/", `\`))
	body := make([]byte, 56+len(u))
	smb2le.PutUint16(body[0:2], 57)
	body[2] = 0
	smb2le.PutUint32(body[8:12], access)
	smb2le.PutUint32(body[24:28], fileShareRead|fileShareWrite|fileShareDelete)
	smb2le.PutUint32(body[28:32], fileOpen)
	smb2le.PutUint32(body[32:36], options)
	smb2le.PutUint32(body[36:40], 0)
	off := uint16(smb2HeaderSize + 56)
	if len(u) == 0 {
		off = 0
	}
	smb2le.PutUint16(body[44:46], off)
	smb2le.PutUint16(body[46:48], uint16(len(u)))
	copy(body[56:], u)
	hdr, payload, err := s.roundtripPayload(smb2Create, s.sessionID, tid, body)
	if err != nil {
		return zero, err
	}
	if statusOf(hdr) != 0 {
		return zero, fmt.Errorf("smb create %q status=0x%08x", name, statusOf(hdr))
	}
	if len(payload) < 16+64 {
		return zero, fmt.Errorf("smb create response too short")
	}
	var fid [16]byte
	copy(fid[:], payload[64:80])
	return fid, nil
}

func (s *krbSession) closeFID(tid uint32, fid [16]byte) {
	body := make([]byte, 24)
	smb2le.PutUint16(body[0:2], 24)
	copy(body[8:24], fid[:])
	_, _, _ = s.roundtripPayload(smb2Close, s.sessionID, tid, body)
}

func (s *krbSession) queryDirectory(tid uint32, fid [16]byte) ([]byte, error) {
	star := utf16le("*")
	body := make([]byte, 32+len(star))
	smb2le.PutUint16(body[0:2], 33)
	body[2] = fileInfoFileDirectory
	copy(body[8:24], fid[:])
	smb2le.PutUint16(body[24:26], smb2HeaderSize+32)
	smb2le.PutUint16(body[26:28], uint16(len(star)))
	smb2le.PutUint32(body[28:32], 0x10000)
	copy(body[32:], star)
	hdr, payload, err := s.roundtripPayload(smb2QueryDirectory, s.sessionID, tid, body)
	if err != nil {
		return nil, err
	}
	if statusOf(hdr) != 0 {
		return nil, fmt.Errorf("query directory status=0x%08x", statusOf(hdr))
	}
	if len(payload) < 8 {
		return nil, fmt.Errorf("query directory short")
	}
	off := int(smb2le.Uint16(payload[2:4]))
	n := int(smb2le.Uint32(payload[4:8]))
	if off < smb2HeaderSize {
		off = 0
		if n > len(payload) {
			return payload, nil
		}
		return payload[:n], nil
	}
	off -= smb2HeaderSize
	if off < 0 || off+n > len(payload) {
		return payload, nil
	}
	return payload[off : off+n], nil
}

func (s *krbSession) readAll(tid uint32, fid [16]byte) ([]byte, error) {
	var out []byte
	var offset uint64
	for {
		chunk, err := s.readFIDAt(tid, fid, offset, 64*1024)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			break
		}
		out = append(out, chunk...)
		if len(out) > maxDownloadBytes {
			return nil, fmt.Errorf("file too large: max %d bytes", maxDownloadBytes)
		}
		if len(chunk) < 64*1024 {
			break
		}
		offset += uint64(len(chunk))
	}
	return out, nil
}

func (s *krbSession) readFID(tid uint32, fid [16]byte, n uint32) ([]byte, error) {
	return s.readFIDAt(tid, fid, 0, n)
}

func (s *krbSession) readFIDAt(tid uint32, fid [16]byte, offset uint64, n uint32) ([]byte, error) {
	body := make([]byte, 48)
	smb2le.PutUint16(body[0:2], 49)
	smb2le.PutUint32(body[4:8], n)
	smb2le.PutUint64(body[8:16], offset)
	copy(body[16:32], fid[:])
	smb2le.PutUint32(body[32:36], 0)
	hdr, payload, err := s.roundtripPayload(smb2Read, s.sessionID, tid, body)
	if err != nil {
		return nil, err
	}
	if statusOf(hdr) != 0 {
		return nil, fmt.Errorf("smb read status=0x%08x", statusOf(hdr))
	}
	if len(payload) < 16 {
		return nil, fmt.Errorf("smb read short")
	}
	dataOff := int(payload[2])
	dataLen := int(smb2le.Uint32(payload[4:8]))
	dataOff -= smb2HeaderSize
	if dataOff < 0 || dataOff+dataLen > len(payload) {
		if dataLen <= len(payload) {
			return payload[len(payload)-dataLen:], nil
		}
		return payload, nil
	}
	return payload[dataOff : dataOff+dataLen], nil
}

func (s *krbSession) writeFID(tid uint32, fid [16]byte, data []byte) (int, error) {
	body := make([]byte, 48+len(data))
	smb2le.PutUint16(body[0:2], 49)
	smb2le.PutUint16(body[2:4], smb2HeaderSize+48)
	smb2le.PutUint32(body[4:8], uint32(len(data)))
	copy(body[16:32], fid[:])
	copy(body[48:], data)
	hdr, payload, err := s.roundtripPayload(smb2Write, s.sessionID, tid, body)
	if err != nil {
		return 0, err
	}
	if statusOf(hdr) != 0 {
		return 0, fmt.Errorf("smb write status=0x%08x", statusOf(hdr))
	}
	if len(payload) >= 8 {
		return int(smb2le.Uint32(payload[4:8])), nil
	}
	return len(data), nil
}

func (s *krbSession) roundtrip(cmd uint16, sid uint64, tid uint32, body []byte) ([]byte, error) {
	hdr, _, err := s.roundtripPayload(cmd, sid, tid, body)
	return hdr, err
}

func (s *krbSession) roundtripPayload(cmd uint16, sid uint64, tid uint32, body []byte) ([]byte, []byte, error) {
	hdr := make([]byte, smb2HeaderSize)
	copy(hdr[0:4], smb2Protocol)
	smb2le.PutUint16(hdr[4:6], smb2HeaderSize)
	smb2le.PutUint16(hdr[12:14], cmd)
	smb2le.PutUint16(hdr[14:16], 1)
	smb2le.PutUint64(hdr[24:32], s.msgID)
	s.msgID++
	smb2le.PutUint32(hdr[36:40], tid)
	smb2le.PutUint64(hdr[40:48], sid)
	pkt := append(hdr, body...)
	s.sign(pkt)
	if err := writeDirect(s.conn, pkt); err != nil {
		return nil, nil, err
	}
	resp, err := readDirect(s.conn)
	if err != nil {
		return nil, nil, err
	}
	if len(resp) < smb2HeaderSize {
		return nil, nil, fmt.Errorf("smb response too short")
	}
	return resp[:smb2HeaderSize], resp[smb2HeaderSize:], nil
}

func (s *krbSession) sign(pkt []byte) {
	if s == nil || s.sessionID == 0 || len(s.sessionKey) == 0 || len(pkt) < smb2HeaderSize {
		return
	}
	flags := smb2le.Uint32(pkt[16:20]) | smb2FlagsSigned
	smb2le.PutUint32(pkt[16:20], flags)
	for i := 48; i < 64; i++ {
		pkt[i] = 0
	}
	mac := hmac.New(sha256.New, s.sessionKey)
	mac.Write(pkt)
	copy(pkt[48:64], mac.Sum(nil)[:16])
}

func writeDirect(c net.Conn, pkt []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(pkt)))
	if _, err := c.Write(n[:]); err != nil {
		return err
	}
	_, err := c.Write(pkt)
	return err
}

func readDirect(c net.Conn) ([]byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return nil, err
	}
	l := binary.BigEndian.Uint32(n[:])
	if l == 0 || l > 4<<20 {
		return nil, fmt.Errorf("smb frame %d", l)
	}
	buf := make([]byte, l)
	_, err := io.ReadFull(c, buf)
	return buf, err
}

func statusOf(hdr []byte) uint32 {
	return smb2le.Uint32(hdr[8:12])
}

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, r := range u {
		smb2le.PutUint16(b[i*2:], r)
	}
	return b
}

func parseDirInfo(b []byte) []string {
	var out []string
	off := 0
	for off+64 <= len(b) {
		next := int(smb2le.Uint32(b[off:]))
		nameLen := int(smb2le.Uint32(b[off+60:]))
		nameOff := off + 64
		if nameOff+nameLen > len(b) {
			break
		}
		name := decodeUTF16(b[nameOff : nameOff+nameLen])
		if name != "" && name != "." && name != ".." {
			out = append(out, name)
		}
		if next == 0 {
			break
		}
		off += next
	}
	return out
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = smb2le.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func bAt(b []byte, i int) byte {
	if i < 0 || i >= len(b) {
		return 0
	}
	return b[i]
}

func srvsvcBind(callID uint32) []byte {
	b := make([]byte, 72)
	b[0], b[1], b[2], b[3] = 5, 0, 11, 0x03
	b[4] = 0x10
	smb2le.PutUint16(b[8:10], 72)
	smb2le.PutUint32(b[12:16], callID)
	smb2le.PutUint16(b[16:18], 4280)
	smb2le.PutUint16(b[18:20], 4280)
	smb2le.PutUint32(b[24:28], 1)
	smb2le.PutUint16(b[30:32], 1)
	_, _ = hex.Decode(b[32:48], []byte("c84f324b7016d30112785a47bf6ee188"))
	smb2le.PutUint16(b[48:50], 3)
	_, _ = hex.Decode(b[52:68], []byte("045d888aeb1cc9119fe808002b104860"))
	smb2le.PutUint32(b[68:72], 2)
	return b
}

func netShareEnumAll(callID uint32, server string) []byte {
	name := utf16le(server + "\x00")
	count := len(name) / 2
	off := 40 + len(name)
	if off%4 != 0 {
		off += 4 - off%4
	}
	off += 28
	b := make([]byte, off)
	b[0], b[1], b[2], b[3] = 5, 0, 0, 0x03
	b[4] = 0x10
	smb2le.PutUint16(b[8:10], uint16(off))
	smb2le.PutUint32(b[12:16], callID)
	smb2le.PutUint32(b[16:20], uint32(off-24))
	smb2le.PutUint16(b[22:24], 15)
	smb2le.PutUint32(b[24:28], 0x20000)
	smb2le.PutUint32(b[28:32], uint32(count))
	smb2le.PutUint32(b[36:40], uint32(count))
	copy(b[40:], name)
	p := 40 + len(name)
	if p%4 != 0 {
		p += 4 - p%4
	}
	smb2le.PutUint32(b[p:p+4], 1)
	smb2le.PutUint32(b[p+4:p+8], 1)
	smb2le.PutUint32(b[p+8:p+12], 0x20004)
	smb2le.PutUint32(b[p+20:p+24], 0xffffffff)
	return b
}

func parseNetShareEnum(resp []byte) ([]string, error) {
	if len(resp) < 24 {
		return nil, fmt.Errorf("srvsvc enum short")
	}
	var names []string
	// Scan UTF-16 share-like tokens (C$, ADMIN$, IPC$, SYSVOL, …).
	for i := 24; i+4 < len(resp); i += 2 {
		if resp[i+1] != 0 {
			continue
		}
		if resp[i] < 'A' || (resp[i] > 'Z' && resp[i] < 'a') || resp[i] > 'z' {
			continue
		}
		var u []uint16
		for j := i; j+1 < len(resp); j += 2 {
			c := smb2le.Uint16(resp[j:])
			if c == 0 {
				break
			}
			if c > 127 {
				u = nil
				break
			}
			u = append(u, c)
		}
		if len(u) < 1 || len(u) > 80 {
			continue
		}
		n := string(utf16.Decode(u))
		if strings.ContainsAny(n, " \t") {
			continue
		}
		names = append(names, n)
		i += len(u) * 2
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("srvsvc enum: no share names")
	}
	return uniqueShareNames(names), nil
}

func uniqueShareNames(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range in {
		k := strings.ToLower(n)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, n)
	}
	return out
}
