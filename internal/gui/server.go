// Package gui serves the browser interface from the binary. By default it
// listens on the loopback address only and trusts a one-time launch link;
// server mode (Config.Listen) is for containers and relies on the vault's own
// unlock as the login.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"
)

//go:embed web
var webFiles embed.FS

const (
	cookieName  = "otpmh_session"
	idleTimeout = 5 * time.Minute
	maxAge      = 24 * time.Hour
)

type Config struct {
	VaultPath string
	// Port is the local-mode port; 0 picks a free one.
	Port int
	// Listen switches on server mode (for example ":8080").
	Listen       string
	TLSCert      string
	TLSKey       string
	AllowedHosts []string
	InsecureHTTP bool
}

type Server struct {
	cfg          Config
	remote       bool
	https        bool
	allowedHosts []string
	launchToken  string
	tokenUsed    atomic.Bool
	setupCode    string
	sessions     *sessions
	limiter      *limiter
	now          func() time.Time
	addr         string
}

func New(cfg Config) (*Server, error) {
	remote := cfg.Listen != ""
	https := cfg.TLSCert != "" || cfg.TLSKey != ""
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, errors.New("--tls-cert and --tls-key must be given together")
	}
	if remote && !https && !cfg.InsecureHTTP {
		return nil, errors.New("server mode over plain HTTP is refused: use --tls-cert and --tls-key, or pass --insecure-http when TLS ends at a proxy or the port is only published on the host's loopback")
	}

	s := &Server{cfg: cfg, remote: remote, https: https, now: time.Now}
	s.sessions = newSessions(s.clock, idleTimeout, maxAge)
	s.limiter = newLimiter(s.clock)

	if remote {
		s.allowedHosts = cfg.AllowedHosts
		var err error
		if s.setupCode, err = randomHex(6); err != nil {
			return nil, err
		}
		return s, nil
	}
	var err error
	if s.launchToken, err = randomHex(32); err != nil {
		return nil, err
	}
	if cfg.Port != 0 {
		s.setLocalHosts(cfg.Port)
	}
	return s, nil
}

func (s *Server) clock() time.Time { return s.now() }

func (s *Server) setLocalHosts(port int) {
	p := strconv.Itoa(port)
	s.allowedHosts = []string{"127.0.0.1:" + p, "localhost:" + p}
}

func randomHex(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// SetupCode is the one-time code that authorizes creating the first vault in
// server mode (shown in the server's own output); empty in local mode.
func (s *Server) SetupCode() string { return s.setupCode }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok\n")) // a failed write to the client has no recovery
	})
	s.registerAPI(mux)

	web, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic("gui: embedded web files missing: " + err.Error())
	}
	files := http.FileServer(http.FS(web))
	mux.Handle("/", s.launch(files))

	return securityHeaders(s.checkHost(mux))
}

// launch swaps the one-time token in the launch link for the session cookie.
func (s *Server) launch(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("t")
		if token == "" || s.remote {
			next.ServeHTTP(w, r)
			return
		}
		valid := subtle.ConstantTimeCompare([]byte(token), []byte(s.launchToken)) == 1
		if !valid || !s.tokenUsed.CompareAndSwap(false, true) {
			http.Error(w, "this launch link was already used; start otpmh again to get a new one", http.StatusForbidden)
			return
		}
		s.setCookie(w, s.sessions.create())
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

func (s *Server) setCookie(w http.ResponseWriter, sess *session) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: sess.id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: s.https,
		MaxAge: int(maxAge.Seconds()),
	})
}

// sessionOf returns the caller's session, or nil.
func (s *Server) sessionOf(r *http.Request) *session {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	return s.sessions.get(c.Value)
}

// LaunchURL is the link that opens the interface in local mode.
func (s *Server) LaunchURL() string {
	return fmt.Sprintf("http://%s/?t=%s", s.addr, s.launchToken)
}

// Run serves until ctx ends. open, if not nil, is called with the launch link
// in local mode once the server is listening.
func (s *Server) Run(ctx context.Context, open func(url string)) error {
	addr := s.cfg.Listen
	if !s.remote {
		addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(s.cfg.Port))
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.addr = ln.Addr().String()
	if !s.remote {
		s.setLocalHosts(ln.Addr().(*net.TCPAddr).Port)
	}

	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() {
		if s.https {
			errc <- srv.ServeTLS(ln, s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	if open != nil && !s.remote {
		open(s.LaunchURL())
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	s.sessions.closeAll()
	return err
}

func init() {
	// Go's built-in table has no entry for web fonts.
	_ = mime.AddExtensionType(".woff2", "font/woff2")
}
