package gui

import (
	"encoding/json"
	"net/http"

	"github.com/rutvik24/otp-migration-helper/internal/vault"
)

const maxJSONBody = 1 << 20

// api wraps a handler that needs a browser session (created by the launch link).
func (s *Server) api(h func(http.ResponseWriter, *http.Request, *session)) http.Handler {
	return requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionOf(r)
		if sess == nil {
			writeError(w, http.StatusUnauthorized, "Your session has ended. Reload this page, or start otpmh again for a new link.")
			return
		}
		h(w, r, sess)
	}))
}

// authed wraps a handler that needs an unlocked vault.
func (s *Server) authed(h func(http.ResponseWriter, *http.Request, *vault.Session)) http.Handler {
	return s.api(func(w http.ResponseWriter, r *http.Request, sess *session) {
		v := sess.vaultSession()
		if v == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "The vault is locked. Unlock it to continue.", "locked": true})
			return
		}
		h(w, r, v)
	})
}

// open wraps a handler for the screens before unlocking. In server mode there
// is no launch link, so the browser may not have a session yet (sess is nil);
// handlers that succeed call s.ensure to start one.
func (s *Server) open(h func(http.ResponseWriter, *http.Request, *session)) http.Handler {
	if !s.remote {
		return s.api(h)
	}
	return requireCSRF(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h(w, r, s.sessionOf(r))
	}))
}

// ensure returns sess, starting a session (and its cookie) when there is none.
func (s *Server) ensure(w http.ResponseWriter, sess *session) *session {
	if sess != nil {
		return sess
	}
	sess = s.sessions.create()
	s.setCookie(w, sess)
	return sess
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "The request was not understood. Reload the page and try again.")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client went away; nothing else to do
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
