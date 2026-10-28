package gui

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/vault"
)

// session is one browser's login: it holds the unlocked vault, if any.
type session struct {
	id       string
	mu       sync.Mutex
	v        *vault.Session
	created  time.Time
	lastSeen time.Time
	// verifiedUntil is when the user's last "confirm it's you" expires.
	verifiedUntil time.Time
}

func (s *session) markVerified(until time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifiedUntil = until
}

func (s *session) verified(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return now.Before(s.verifiedUntil)
}

func (s *session) vaultSession() *vault.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v
}

// setVault replaces the unlocked vault, closing the previous one.
func (s *session) setVault(v *vault.Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v != nil {
		_ = s.v.Close() // the data key is wiped even if the file close fails
	}
	s.v = v
	s.verifiedUntil = time.Time{} // locking or unlocking always starts unverified
}

type sessions struct {
	mu     sync.Mutex
	m      map[string]*session
	now    func() time.Time
	idle   time.Duration
	maxAge time.Duration
}

func newSessions(now func() time.Time, idle, maxAge time.Duration) *sessions {
	return &sessions{m: map[string]*session{}, now: now, idle: idle, maxAge: maxAge}
}

func (ss *sessions) create() *session {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic("gui: no randomness available: " + err.Error())
	}
	now := ss.now()
	s := &session{id: base64.RawURLEncoding.EncodeToString(raw), created: now, lastSeen: now}
	ss.mu.Lock()
	ss.m[s.id] = s
	ss.mu.Unlock()
	return s
}

// get returns the session for an id, locking it after the idle timeout and
// dropping it after its maximum age. It returns nil for unknown sessions.
func (ss *sessions) get(id string) *session {
	ss.mu.Lock()
	s := ss.m[id]
	if s == nil {
		ss.mu.Unlock()
		return nil
	}
	now := ss.now()
	if now.Sub(s.created) > ss.maxAge {
		delete(ss.m, id)
		ss.mu.Unlock()
		s.setVault(nil)
		return nil
	}
	idle := now.Sub(s.lastSeen) > ss.idle
	s.lastSeen = now
	ss.mu.Unlock()
	if idle {
		s.setVault(nil)
	}
	return s
}

func (ss *sessions) closeAll() {
	ss.mu.Lock()
	all := make([]*session, 0, len(ss.m))
	for _, s := range ss.m {
		all = append(all, s)
	}
	ss.m = map[string]*session{}
	ss.mu.Unlock()
	for _, s := range all {
		s.setVault(nil)
	}
}
