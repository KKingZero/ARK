package smbcli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/hirochachacha/go-smb2"
)

const pipeReadMax = 0x10000

// Pipe is one DCERPC association: same IPC$ tree and named-pipe FID
// for bind plus every subsequent call.
type Pipe struct {
	s    *Session
	name string
	mu   sync.Mutex

	share *smb2.Share
	file  *smb2.File

	tid  uint32
	fid  [16]byte
	kerb bool
}

// OpenPipe mounts IPC$ (once per session) and opens the named pipe.
func (s *Session) OpenPipe(name string) (*Pipe, error) {
	if s == nil {
		return nil, fmt.Errorf("smb session required")
	}
	name = strings.TrimPrefix(strings.ReplaceAll(name, `/`, `\`), `\`)
	if name == "" {
		return nil, fmt.Errorf("pipe name required")
	}
	p := &Pipe{s: s, name: name}
	if s.kerb != nil {
		tid, err := s.kerb.tree("IPC$")
		if err != nil {
			return nil, err
		}
		fid, err := s.kerb.create(tid, name, fileReadData|0x0002, fileNonDirectoryFile)
		if err != nil {
			return nil, fmt.Errorf("open pipe %s: %w", name, err)
		}
		p.kerb = true
		p.tid = tid
		p.fid = fid
		return p, nil
	}
	if s.inner == nil {
		return nil, fmt.Errorf("smb session has no transport")
	}
	fs, err := s.inner.Mount("IPC$")
	if err != nil {
		return nil, fmt.Errorf("mount IPC$: %w", err)
	}
	f, err := fs.OpenFile(name, os.O_RDWR, 0666)
	if err != nil {
		_ = fs.Umount()
		return nil, fmt.Errorf("open pipe %s: %w", name, err)
	}
	p.share = fs
	p.file = f
	return p, nil
}

// Transceive writes then reads on the same FID (DCERPC request/response).
func (p *Pipe) Transceive(input []byte) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("pipe required")
	}
	if len(input) == 0 {
		return nil, fmt.Errorf("payload required")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.kerb {
		if p.s == nil || p.s.kerb == nil {
			return nil, fmt.Errorf("pipe closed")
		}
		if _, err := p.s.kerb.writeFID(p.tid, p.fid, input); err != nil {
			return nil, fmt.Errorf("write pipe %s: %w", p.name, err)
		}
		return p.s.kerb.readFID(p.tid, p.fid, pipeReadMax)
	}
	if p.file == nil {
		return nil, fmt.Errorf("pipe closed")
	}
	if _, err := p.file.Write(input); err != nil {
		return nil, fmt.Errorf("write pipe %s: %w", p.name, err)
	}
	buf := make([]byte, pipeReadMax)
	n, err := p.file.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read pipe %s: %w", p.name, err)
	}
	return buf[:n], nil
}

// Close releases the pipe FID (and NTLM IPC$ tree for this pipe).
func (p *Pipe) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.kerb {
		if p.s != nil && p.s.kerb != nil {
			p.s.kerb.closeFID(p.tid, p.fid)
		}
		p.s = nil
		return nil
	}
	if p.file != nil {
		_ = p.file.Close()
		p.file = nil
	}
	if p.share != nil {
		_ = p.share.Umount()
		p.share = nil
	}
	return nil
}

// PipeTransceive is a one-shot helper (open, one PDU, close).
// DCERPC bind+call sequences must use OpenPipe and keep the FID.
func (s *Session) PipeTransceive(pipe string, input []byte) ([]byte, error) {
	p, err := s.OpenPipe(pipe)
	if err != nil {
		return nil, err
	}
	defer p.Close()
	return p.Transceive(input)
}
