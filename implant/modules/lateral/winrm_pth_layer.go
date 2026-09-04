package lateral

import (
	"errors"
	"fmt"
)

// PTHLayer names which WinRM hash-only step failed.
type PTHLayer string

const (
	PTHLayerTransport     PTHLayer = "transport"
	PTHLayerHTTPNegotiate PTHLayer = "http_negotiate"
	PTHLayerNTLMHandshake PTHLayer = "ntlm_handshake"
	PTHLayerKeyDerivation PTHLayer = "key_derivation"
	PTHLayerSignSeal      PTHLayer = "sign_seal"
	PTHLayerWinRMMIME     PTHLayer = "winrm_mime"
	PTHLayerSessionLife   PTHLayer = "session_lifecycle"
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

// PTHDiagnose returns the named layer if err was classified.
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
	return pthWrap(PTHLayerTransport, err)
}
