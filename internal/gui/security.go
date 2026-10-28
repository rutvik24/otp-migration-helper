package gui

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	csrfHeader = "X-Requested-With"
	csrfValue  = "otpmh"

	delayAfterFailures = 3
	blockAfterFailures = 10
	maxDelay           = 5 * time.Minute
	blockFor           = 15 * time.Minute
)

// contentSecurityPolicy lets the page use only its own files; the camera
// preview is a blob: media stream and decoded frames stay in the page.
const contentSecurityPolicy = "default-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; " +
	"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(self), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

// hostAllowed blocks DNS-rebinding: only the names this server expects are served.
func (s *Server) hostAllowed(host string) bool {
	if len(s.allowedHosts) == 0 {
		return true
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	for _, allowed := range s.allowedHosts {
		if allowed == host || allowed == name {
			return true
		}
	}
	return false
}

func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			http.Error(w, "unexpected host name", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireCSRF rejects state-changing requests that a plain cross-site form
// could send: they must carry a custom header.
func requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get(csrfHeader) != csrfValue {
				http.Error(w, "missing request header", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

type attempt struct {
	failures int
	until    time.Time
}

// limiter slows repeated failed unlock/recovery attempts per client address.
type limiter struct {
	mu  sync.Mutex
	now func() time.Time
	m   map[string]*attempt
}

func newLimiter(now func() time.Time) *limiter {
	return &limiter{now: now, m: map[string]*attempt{}}
}

// wait returns how long the client must wait before the next attempt.
func (l *limiter) wait(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil {
		return 0
	}
	if d := a.until.Sub(l.now()); d > 0 {
		return d
	}
	return 0
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.m[ip]
	if a == nil {
		a = &attempt{}
		l.m[ip] = a
	}
	a.failures++
	switch {
	case a.failures >= blockAfterFailures:
		a.until = l.now().Add(blockFor)
	case a.failures >= delayAfterFailures:
		delay := time.Second << (a.failures - delayAfterFailures)
		a.until = l.now().Add(min(delay, maxDelay))
	}
}

func (l *limiter) ok(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, ip)
}
