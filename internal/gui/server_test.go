package gui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/vault"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

func TestMain(m *testing.M) {
	vaultcrypto.SetWorkFactorForTests(10)
	os.Exit(m.Run())
}

const localHost = "127.0.0.1:4040"

func newLocal(t *testing.T) *Server {
	t.Helper()
	s, err := New(Config{VaultPath: filepath.Join(t.TempDir(), "vault.db"), Port: 4040})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func do(s *Server, method, target, host string, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.Host = host
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// launch exchanges the one-time token for the session cookie.
func launch(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	rec := do(s, "GET", "/?t="+s.launchToken, localHost, nil)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("launch status %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("no session cookie issued")
	return nil
}

func TestHost_WrongHostRejected(t *testing.T) {
	s := newLocal(t)
	for _, host := range []string{"evil.example", "evil.example:4040", "127.0.0.1:9999"} {
		if rec := do(s, "GET", "/", host, nil); rec.Code != http.StatusForbidden {
			t.Errorf("host %q: status %d, want 403", host, rec.Code)
		}
	}
	if rec := do(s, "GET", "/", "localhost:4040", nil); rec.Code != http.StatusOK {
		t.Errorf("localhost: status %d", rec.Code)
	}
	if rec := do(s, "GET", "/healthz", "anything.example", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz should answer for any host: %d", rec.Code)
	}
}

func TestHealthz_NoAuth(t *testing.T) {
	s := newLocal(t)
	rec := do(s, "GET", "/healthz", localHost, nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Errorf("status %d body %q", rec.Code, rec.Body.String())
	}
}

func TestAPI_NoCookie401(t *testing.T) {
	s := newLocal(t)
	if rec := do(s, "GET", "/api/status", localHost, nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", rec.Code)
	}
}

func TestLocalToken_WorksOnce(t *testing.T) {
	s := newLocal(t)
	cookie := launch(t, s)
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("cookie flags: %+v", cookie)
	}
	if rec := do(s, "GET", "/?t="+s.launchToken, localHost, nil); rec.Code != http.StatusForbidden {
		t.Errorf("token reuse: status %d, want 403", rec.Code)
	}
	if rec := do(s, "GET", "/api/status", localHost, nil, cookie); rec.Code != http.StatusOK {
		t.Errorf("status with cookie: %d", rec.Code)
	}
}

func TestCSRF_PostWithoutHeader403(t *testing.T) {
	s := newLocal(t)
	cookie := launch(t, s)
	if rec := do(s, "POST", "/api/lock", localHost, nil, cookie); rec.Code != http.StatusForbidden {
		t.Errorf("without header: %d, want 403", rec.Code)
	}
	if rec := do(s, "POST", "/api/lock", localHost, map[string]string{"X-Requested-With": "otpmh"}, cookie); rec.Code != http.StatusOK {
		t.Errorf("with header: %d", rec.Code)
	}
}

func TestHeaders_NoStoreAndCSP(t *testing.T) {
	s := newLocal(t)
	h := do(s, "GET", "/", localHost, nil).Header()
	if h.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control: %q", h.Get("Cache-Control"))
	}
	csp := h.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "http") {
		t.Errorf("CSP: %q", csp)
	}
	if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("headers: %v", h)
	}
}

func TestRemote_PlainHTTPRefusedWithoutOptIn(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(Config{VaultPath: filepath.Join(dir, "v.db"), Listen: ":8080"}); err == nil {
		t.Error("plain HTTP server mode must be refused without opt-in")
	}
	if _, err := New(Config{VaultPath: filepath.Join(dir, "v.db"), Listen: ":8080", InsecureHTTP: true}); err != nil {
		t.Errorf("opt-in should work: %v", err)
	}
	if _, err := New(Config{VaultPath: filepath.Join(dir, "v.db"), Listen: ":8080", TLSCert: "cert.pem"}); err == nil {
		t.Error("a certificate without a key must be refused")
	}
}

func TestRemote_AllowedHosts(t *testing.T) {
	s, err := New(Config{VaultPath: filepath.Join(t.TempDir(), "v.db"), Listen: ":8080", InsecureHTTP: true, AllowedHosts: []string{"otp.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(s, "GET", "/", "otp.example.com", nil); rec.Code != http.StatusOK {
		t.Errorf("allowed host: %d", rec.Code)
	}
	if rec := do(s, "GET", "/", "otp.example.com:8443", nil); rec.Code != http.StatusOK {
		t.Errorf("allowed host with port: %d", rec.Code)
	}
	if rec := do(s, "GET", "/", "evil.example", nil); rec.Code != http.StatusForbidden {
		t.Errorf("other host: %d", rec.Code)
	}
}

func TestSession_LocksAfterIdle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	if _, err := vault.Create(path, vault.CreateOptions{Setup: vaultcrypto.Setup{Mode: vaultcrypto.Password, Password: "pw"}, NoRecovery: true}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	ss := newSessions(func() time.Time { return now }, 5*time.Minute, 24*time.Hour)
	sess := ss.create()
	v, err := vault.Open(path, vault.Creds{Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	sess.setVault(v)

	now = now.Add(4 * time.Minute)
	if got := ss.get(sess.id); got == nil || got.vaultSession() == nil {
		t.Fatal("locked too early")
	}
	now = now.Add(4*time.Minute + time.Second) // 4m01s since the last request: still fine
	if got := ss.get(sess.id); got == nil || got.vaultSession() == nil {
		t.Fatal("activity should extend the session")
	}
	now = now.Add(5*time.Minute + time.Second)
	got := ss.get(sess.id)
	if got == nil || got.vaultSession() != nil {
		t.Error("idle session should be locked")
	}
	now = now.Add(25 * time.Hour)
	if ss.get(sess.id) != nil {
		t.Error("old session should be gone")
	}
}

func TestLimiter_DelaysThenBlocks(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newLimiter(func() time.Time { return now })
	for i := 0; i < 2; i++ {
		l.fail("1.2.3.4")
	}
	if wait := l.wait("1.2.3.4"); wait != 0 {
		t.Errorf("two failures should not delay: %v", wait)
	}
	l.fail("1.2.3.4")
	if wait := l.wait("1.2.3.4"); wait <= 0 {
		t.Error("third failure should delay")
	}
	now = now.Add(10 * time.Second)
	if wait := l.wait("1.2.3.4"); wait != 0 {
		t.Errorf("delay should pass: %v", wait)
	}
	for i := 0; i < 7; i++ {
		l.fail("1.2.3.4")
	}
	if wait := l.wait("1.2.3.4"); wait < 10*time.Minute {
		t.Errorf("tenth failure should block ~15m, got %v", wait)
	}
	if wait := l.wait("9.9.9.9"); wait != 0 {
		t.Error("other clients are unaffected")
	}
	l.ok("1.2.3.4")
	if wait := l.wait("1.2.3.4"); wait != 0 {
		t.Error("success clears the record")
	}
}
