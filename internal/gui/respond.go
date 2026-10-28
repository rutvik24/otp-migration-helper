package gui

import (
	"encoding/json"
	"net/http"
)

// api wraps a handler that needs a logged-in browser session and a CSRF header.
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // the client went away; nothing else to do
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
