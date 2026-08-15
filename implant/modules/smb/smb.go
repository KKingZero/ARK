package smb

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/KKingZero/erebus-exploit-framwork/pkg/pb"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/plugin"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/smbcli"
	"github.com/KKingZero/erebus-exploit-framwork/pkg/suggestions"
	"google.golang.org/protobuf/proto"
)

func init() {
	plugin.Global.Register(&SMBModule{})
}

// SMBModule is a remote SMB client (list shares, list dir, download).
type SMBModule struct{}

func (m *SMBModule) Name() string        { return "smb" }
func (m *SMBModule) Description() string { return "Remote SMB share list/list_dir/download" }

func (m *SMBModule) Execute(ctx context.Context, config []byte) ([]byte, error) {
	cfg := &pb.SMBClientConfig{}
	if err := proto.Unmarshal(config, cfg); err != nil {
		return nil, fmt.Errorf("unmarshal smb config: %w", err)
	}
	result, err := runSMB(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(result)
}

func runSMB(ctx context.Context, cfg *pb.SMBClientConfig) (*pb.SMBClientResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("host required")
	}
	action := strings.ToLower(strings.TrimSpace(cfg.Action))
	if action == "" {
		action = "list_shares"
	}

	sess, err := smbcli.Dial(smbcli.Options{
		Host:      cfg.Host,
		Domain:    cfg.Domain,
		Username:  cfg.Username,
		Password:  cfg.Password,
		Hash:      cfg.NtlmHash,
		Anonymous: cfg.Anonymous,
	})
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	result := &pb.SMBClientResult{
		Action: action,
		Host:   cfg.Host,
		Share:  cfg.Share,
		Path:   cfg.Path,
	}

	switch action {
	case "list_shares", "shares":
		names, err := sess.ListShares()
		if err != nil {
			return nil, err
		}
		result.Names = names
	case "list_dir", "ls", "dir":
		names, err := sess.ListDir(cfg.Share, cfg.Path)
		if err != nil {
			return nil, err
		}
		result.Names = names
	case "download", "get":
		data, err := sess.Download(cfg.Share, cfg.Path)
		if err != nil {
			return nil, err
		}
		result.FileData = data
		result.FileSize = int64(len(data))
		result.Path = smbcli.NormalizePath(cfg.Path)
	default:
		return nil, fmt.Errorf("unknown smb action %q (list_shares|list_dir|download)", action)
	}
	result.NextSuggestedActions = suggestions.ForSMB(result)
	return result, nil
}
