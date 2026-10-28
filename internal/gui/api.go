package gui

import "net/http"

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.Handle("GET /api/status", s.api(func(w http.ResponseWriter, r *http.Request, sess *session) {
		writeJSON(w, http.StatusOK, map[string]any{"unlocked": sess.vaultSession() != nil})
	}))
	mux.Handle("POST /api/lock", s.api(func(w http.ResponseWriter, r *http.Request, sess *session) {
		sess.setVault(nil)
		writeJSON(w, http.StatusOK, map[string]any{"unlocked": false})
	}))
}
