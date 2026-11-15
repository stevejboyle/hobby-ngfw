package webui

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	// SessionIdle is how long a session lives without requests.
	SessionIdle = 8 * time.Hour
	cookieName  = "sjb_session"
	csrfHeader  = "X-SJB-CSRF"
)

type session struct {
	user     string
	csrf     string
	lastSeen time.Time
}

type sessions struct {
	mu  sync.Mutex
	m   map[string]*session
	now func() time.Time
}

func token() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *sessions) create(user string) (string, *session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	t := token()
	ss := &session{user: user, csrf: token(), lastSeen: s.now()}
	s.m[t] = ss
	return t, ss
}

func (s *sessions) get(t string) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	ss, ok := s.m[t]
	if !ok {
		return nil
	}
	if s.now().Sub(ss.lastSeen) > SessionIdle {
		delete(s.m, t)
		return nil
	}
	ss.lastSeen = s.now()
	return ss
}

func (s *sessions) drop(t string) {
	s.mu.Lock()
	delete(s.m, t)
	s.mu.Unlock()
}

// dropUser ends every session of user except keep (after a password change).
func (s *sessions) dropUser(user, keep string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for t, ss := range s.m {
		if ss.user == user && t != keep {
			delete(s.m, t)
		}
	}
}

func (s *sessions) expire() {
	for t, ss := range s.m {
		if s.now().Sub(ss.lastSeen) > SessionIdle {
			delete(s.m, t)
		}
	}
}

// limiter slows password guessing: after 5 failures from one address, each
// further attempt is refused for a lockout that doubles up to 15 minutes.
type limiter struct {
	mu  sync.Mutex
	m   map[string]*attempts
	now func() time.Time
}

type attempts struct {
	fails int
	until time.Time
}

const freeFailures = 5

func (l *limiter) blocked(addr string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[addr]
	if a == nil {
		return 0
	}
	if d := a.until.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}

func (l *limiter) fail(addr string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[addr]
	if a == nil {
		a = &attempts{}
		l.m[addr] = a
	}
	a.fails++
	if a.fails >= freeFailures {
		d := 15 * time.Second << min(a.fails-freeFailures, 6)
		a.until = l.now().Add(min(d, 15*time.Minute))
	}
}

func (l *limiter) ok(addr string) {
	l.mu.Lock()
	delete(l.m, addr)
	l.mu.Unlock()
}
