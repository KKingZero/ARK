package lateral

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// PTHLayer is the Day-3 diagnostic gate for WinRM hash-only (PTH).
// A live failure must name exactly one of these before more feature work.
type PTHLayer string

const (
	PTHLayerTransport      PTHLayer = "transport"
	PTHLayerHTTPNegotiate  PTHLayer = "http_negotiate"
	PTHLayerNTLMHandshake  PTHLayer = "ntlm_handshake"
	PTHLayerKeyDerivation  PTHLayer = "key_derivation"
	PTHLayerSignSeal       PTHLayer = "sign_seal"
	PTHLayerWinRMMIME      PTHLayer = "winrm_mime"
	PTHLayerSessionLife    PTHLayer = "session_lifecycle"
)

// pthError tags a WinRM PTH failure with a single protocol layer.
type pthError struct {
	Layer PTHLayer
	Err   error
}

func (e *pthError) Error() string {
	if e == nil || e.Err == nil {
		return "pth_layer=unknown"
	}
	return fmt.Sprintf("pth_layer=%s: %v", e.Layer, e.Err)
}

func (e *pthError) Unwrap() error { return e.Err }

func pthWrap(layer PTHLayer, err error) error {
	if err == nil {
		return nil
	}
	var pe *pthError
	if errors.As(err, &pe) {
		return err
	}
	return &pthError{Layer: layer, Err: err}
}

// PTHDiagnose returns the named layer if err was classified. Day-3 gate:
// if this is false on a live failure, stop feature work and instrument.
func PTHDiagnose(err error) (PTHLayer, bool) {
	var pe *pthError
	if errors.As(err, &pe) && pe.Layer != "" {
		return pe.Layer, true
	}
	return "", false
}

func pthWrapNet(err error) error {
	if err == nil {
		return nil
	}
	var pe *pthError
	if errors.As(err, &pe) {
		return err
	}
	msg := err.Error()
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return pthWrap(PTHLayerTransport, err)
	}
	switch {
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "broken pipe"):
		return pthWrap(PTHLayerTransport, err)
	default:
		return pthWrap(PTHLayerTransport, err)
	}
}
