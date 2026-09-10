package server

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type apiRole string

const (
	roleOperator apiRole = "operator"
	roleApprover apiRole = "approver"
)

func requiredRole(fullMethod string) apiRole {
	name := fullMethod
	if idx := strings.LastIndex(fullMethod, "/"); idx >= 0 {
		name = fullMethod[idx+1:]
	}
	switch name {
	case "Approve", "Deny", "ListPendingApprovals":
		return roleApprover
	default:
		return roleOperator
	}
}

func (ts *Teamserver) authorizeContext(ctx context.Context, fullMethod string) error {
	cn, fingerprint := clientIdentityFromContext(ctx)
	role := requiredRole(fullMethod)
	switch role {
	case roleApprover:
		if ts.authorizedClient(roleApprover, cn, fingerprint) {
			return nil
		}
	case roleOperator:
		if ts.authorizedClient(roleOperator, cn, fingerprint) {
			return nil
		}
	default:
		return status.Errorf(codes.Internal, "unknown API role for %s", fullMethod)
	}
	return status.Error(codes.PermissionDenied, fmt.Sprintf("%s certificate CN %q is not authorized", role, cn))
}

func clientIdentityFromContext(ctx context.Context) (string, string) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", ""
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return "", ""
	}
	cert := tlsInfo.State.PeerCertificates[0]
	sum := sha256.Sum256(cert.Raw)
	return cert.Subject.CommonName, hex.EncodeToString(sum[:])
}

func (ts *Teamserver) authorizedClient(role apiRole, cn, fingerprint string) bool {
	if fps := ts.allowedFP[role]; len(fps) > 0 {
		_, ok := fps[fingerprint]
		return ok
	}
	var cns []string
	switch role {
	case roleApprover:
		cns = ts.Config.ApproverCNs
	default:
		cns = ts.Config.OperatorCNs
	}
	return containsCN(cns, cn)
}

func loadAllowedFingerprints(cfg *Config) map[apiRole]map[string]struct{} {
	out := map[apiRole]map[string]struct{}{
		roleOperator: {},
		roleApprover: {},
	}
	if cfg == nil {
		return out
	}
	add := func(role apiRole, paths []string) {
		for _, path := range paths {
			cert, err := readCertificate(strings.TrimSpace(path))
			if err != nil {
				continue
			}
			sum := sha256.Sum256(cert.Raw)
			out[role][hex.EncodeToString(sum[:])] = struct{}{}
		}
	}
	add(roleOperator, cfg.OperatorCertFiles)
	add(roleApprover, cfg.ApproverCertFiles)
	return out
}

func readCertificate(path string) (*x509.Certificate, error) {
	if path == "" {
		return nil, fmt.Errorf("empty certificate path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (ts *Teamserver) authorizeUnary(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	if err := ts.authorizeContext(ctx, info.FullMethod); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (ts *Teamserver) authorizeStream(
	srv interface{},
	stream grpc.ServerStream,
	info *grpc.StreamServerInfo,
	handler grpc.StreamHandler,
) error {
	if err := ts.authorizeContext(stream.Context(), info.FullMethod); err != nil {
		return err
	}
	return handler(srv, stream)
}
