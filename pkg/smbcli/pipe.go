package smbcli

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// PipeTransceive writes then reads a named pipe on IPC$ (DCERPC).
func (s *Session) PipeTransceive(pipe string, input []byte) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("smb session required")
	}
	pipe = strings.TrimPrefix(strings.ReplaceAll(pipe, `/`, `\`), `\`)
	if pipe == "" || len(input) == 0 {
		return nil, fmt.Errorf("pipe name and payload required")
	}
	if s.kerb != nil {
		tid, err := s.kerb.tree("IPC$")
		if err != nil {
			return nil, err
		}
		fid, err := s.kerb.create(tid, pipe, fileReadData|0x0002, fileNonDirectoryFile)
		if err != nil {
			return nil, fmt.Errorf("open pipe %s: %w", pipe, err)
		}
		defer s.kerb.closeFID(tid, fid)
		if _, err := s.kerb.writeFID(tid, fid, input); err != nil {
			return nil, err
		}
		return s.kerb.readFID(tid, fid, 0x10000)
	}
	if s.inner == nil {
		return nil, fmt.Errorf("smb session has no transport")
	}
	fs, err := s.inner.Mount("IPC$")
	if err != nil {
		return nil, fmt.Errorf("mount IPC$: %w", err)
	}
	defer fs.Umount()
	f, err := fs.OpenFile(pipe, os.O_RDWR, 0666)
	if err != nil {
		return nil, fmt.Errorf("open pipe %s: %w", pipe, err)
	}
	defer f.Close()
	if _, err := f.Write(input); err != nil {
		return nil, fmt.Errorf("write pipe %s: %w", pipe, err)
	}
	buf := make([]byte, 0x10000)
	n, err := f.Read(buf)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read pipe %s: %w", pipe, err)
	}
	return buf[:n], nil
}
