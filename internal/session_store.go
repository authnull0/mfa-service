package session

import (
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

type SessionManager struct {
	store map[string]*webauthn.SessionData
	mu    sync.RWMutex
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		store: make(map[string]*webauthn.SessionData),
	}
}

func (s *SessionManager) Save(key string, data *webauthn.SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = data
}

func (s *SessionManager) Get(key string) (*webauthn.SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, exists := s.store[key]
	return data, exists
}

func (s *SessionManager) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
}
