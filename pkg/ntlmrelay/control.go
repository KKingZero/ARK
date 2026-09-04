package ntlmrelay

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const defaultAPIPort = 18765

// ControlStatePath returns ~/.ark/relay/control.json
func ControlStatePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".ark", "relay", "control.json")
	}
	return filepath.Join(home, ".ark", "relay", "control.json")
}

// ControlState is written by `relay http start` for get/sessions clients.
type ControlState struct {
	API    string `json:"api"`
	Listen string `json:"listen"`
	Target string `json:"target"`
	PID    int    `json:"pid"`
}

// WriteControlState persists control endpoint info.
func WriteControlState(st ControlState) error {
	path := ControlStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// ClearControlState removes the control state file (call on shutdown).
func ClearControlState() {
	_ = os.Remove(ControlStatePath())
}

// ReadControlState loads control endpoint info and verifies the PID is still alive.
func ReadControlState() (ControlState, error) {
	var st ControlState
	b, err := os.ReadFile(ControlStatePath())
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, err
	}
	if st.PID > 0 && !pidAlive(st.PID) {
		ClearControlState()
		return st, fmt.Errorf("relay process pid %d is not running (stale control state cleared)", st.PID)
	}
	return st, nil
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0 checks existence without killing (Unix).
	err = p.Signal(syscall.Signal(0))
	return err == nil
}

// StartControlAPI serves session list / get. Binds loopback only unless allowRemote.
func StartControlAPI(store *SessionStore, addr string, allowRemote bool) (net.Listener, error) {
	if addr == "" {
		addr = fmt.Sprintf("127.0.0.1:%d", defaultAPIPort)
	}
	if err := CheckAPIAddr(addr, allowRemote); err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	var mu sync.Mutex
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		type row struct {
			ID       int    `json:"id"`
			Identity string `json:"identity"`
			Target   string `json:"target"`
			Created  string `json:"created"`
		}
		var rows []row
		for _, s := range store.List() {
			rows = append(rows, row{
				ID:       s.ID,
				Identity: s.Identity(),
				Target:   s.Target,
				Created:  s.CreatedAt.Format(time.RFC3339),
			})
		}
		if rows == nil {
			rows = []row{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rows)
	})
	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id, _ := strconv.Atoi(r.URL.Query().Get("session"))
		path := r.URL.Query().Get("path")
		double := r.URL.Query().Get("double_encode") == "1"
		base := r.URL.Query().Get("base")
		if id == 0 {
			http.Error(w, "session required", http.StatusBadRequest)
			return
		}
		sess, err := store.Get(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		reqPath := path
		if double {
			if base == "" {
				base = "/api/download"
			}
			reqPath = JoinDownloadAPI(base, path, true)
		} else if path != "" && !strings.HasPrefix(path, "/") {
			reqPath = "/" + path
		}
		mu.Lock()
		status, body, err := sess.GetBody(reqPath)
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("X-ARK-Status", strconv.Itoa(status))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() { _ = http.Serve(ln, mux) }()
	return ln, nil
}

// ClientGet downloads via control API.
func ClientGet(apiBase string, sessionID int, path string, doubleEncode bool, base string) (status int, body []byte, err error) {
	q := url.Values{}
	q.Set("session", strconv.Itoa(sessionID))
	q.Set("path", path)
	if doubleEncode {
		q.Set("double_encode", "1")
	}
	if base != "" {
		q.Set("base", base)
	}
	u := strings.TrimRight(apiBase, "/") + "/get?" + q.Encode()
	resp, err := http.Get(u) //nolint:gosec // local control API
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, b, fmt.Errorf("control API: %s: %s", resp.Status, string(b))
	}
	st, _ := strconv.Atoi(resp.Header.Get("X-ARK-Status"))
	return st, b, nil
}

// ClientSessions lists sessions via control API.
func ClientSessions(apiBase string) ([]byte, error) {
	resp, err := http.Get(strings.TrimRight(apiBase, "/") + "/sessions") //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}
