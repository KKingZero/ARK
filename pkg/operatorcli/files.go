package operatorcli

import (
	"fmt"
	"os"
	"strings"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"google.golang.org/protobuf/proto"
)

// maxOpTransferBytes matches the default gRPC message cap. The implant
// allows a larger read (ARK_MAX_FILE_SIZE); this client refuses before the RPC.
const maxOpTransferBytes = 4 << 20

func readUploadFile(local, remote string) (*pb.FileUploadTask, error) {
	local = strings.TrimSpace(local)
	remote = strings.TrimSpace(remote)
	if local == "" || remote == "" {
		return nil, fmt.Errorf("usage: upload <local-path> <remote-path>")
	}
	st, err := os.Stat(local)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("upload: %s is a directory", local)
	}
	if st.Size() > maxOpTransferBytes {
		return nil, fmt.Errorf("upload: %s is %d bytes, limit is %d", local, st.Size(), maxOpTransferBytes)
	}
	b, err := os.ReadFile(local)
	if err != nil {
		return nil, err
	}
	if len(b) > maxOpTransferBytes {
		return nil, fmt.Errorf("upload: %s is %d bytes, limit is %d", local, len(b), maxOpTransferBytes)
	}
	return &pb.FileUploadTask{RemotePath: remote, Data: b}, nil
}

func parseDownloadArgs(args []string) (remote, out string, err error) {
	var pos []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--out" || args[i] == "-o" {
			if i+1 >= len(args) {
				return "", "", fmt.Errorf("usage: download <remote-path> --out <local-path>")
			}
			out = args[i+1]
			i++
			continue
		}
		pos = append(pos, args[i])
	}
	if len(pos) != 1 || strings.TrimSpace(out) == "" || strings.TrimSpace(pos[0]) == "" {
		return "", "", fmt.Errorf("usage: download <remote-path> --out <local-path>")
	}
	return pos[0], out, nil
}

func saveDownloadFile(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("download: --out is required")
	}
	if len(data) > maxOpTransferBytes {
		return fmt.Errorf("download: %d bytes exceeds %d", len(data), maxOpTransferBytes)
	}
	return os.WriteFile(path, data, 0o600)
}

func marshalUpload(task *pb.FileUploadTask) ([]byte, error) {
	if task == nil {
		return nil, fmt.Errorf("upload: empty task")
	}
	return proto.Marshal(task)
}
