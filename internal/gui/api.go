package gui

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/account"
	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/otp"
	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
	"github.com/rutvik24/otp-migration-helper/internal/source"
	"github.com/rutvik24/otp-migration-helper/internal/store"
	"github.com/rutvik24/otp-migration-helper/internal/vault"
	"github.com/rutvik24/otp-migration-helper/internal/vaultcrypto"
)

const (
	totpPeriod    = 30
	maxUploadSize = 10 << 20
	minRecoveryPW = 12
)

func (s *Server) registerAPI(mux *http.ServeMux) {
	mux.Handle("GET /api/status", s.open(s.handleStatus))
	mux.Handle("POST /api/vault", s.open(s.handleCreate))
	mux.Handle("POST /api/unlock", s.open(s.handleUnlock))
	mux.Handle("POST /api/recover", s.open(s.handleRecover))
	mux.Handle("POST /api/lock", s.api(func(w http.ResponseWriter, r *http.Request, sess *session) {
		sess.setVault(nil)
		writeJSON(w, http.StatusOK, map[string]any{"unlocked": false})
	}))

	mux.Handle("GET /api/codes", s.authed(s.handleCodes))
	mux.Handle("POST /api/accounts/{id}/next", s.authed(s.handleNext))
	mux.Handle("GET /api/accounts/{id}/qr.png", s.authed(s.handleQR))
	mux.Handle("GET /api/accounts/{id}/details", s.authed(s.handleDetails))
	mux.Handle("POST /api/decode-image", s.authed(s.handleDecodeImage))
	mux.Handle("POST /api/import/preview", s.authed(s.handlePreview))
	mux.Handle("POST /api/import/commit", s.authed(s.handleCommit))
	mux.Handle("POST /api/export", s.authed(s.handleExport))
	mux.Handle("GET /api/log", s.authed(s.handleLog))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, sess *session) {
	exists := vault.Exists(s.cfg.VaultPath)
	out := map[string]any{"exists": exists, "unlocked": sess != nil && sess.vaultSession() != nil, "remote": s.remote, "setupCodeRequired": s.remote && !exists}
	if exists {
		mode, err := vault.ModeOf(s.cfg.VaultPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "The vault file could not be read.")
			return
		}
		out["mode"] = mode
	}
	writeJSON(w, http.StatusOK, out)
}

type credentialsBody struct {
	Mode               vaultcrypto.Mode `json:"mode"`
	Password           string           `json:"password"`
	SSHPublicKey       string           `json:"sshPublicKey"`
	RecoveryPassphrase string           `json:"recoveryPassphrase"`
	NoRecovery         bool             `json:"noRecovery"`
	SetupCode          string           `json:"setupCode"`
}

// validateSetup checks new credentials without keeping anything, so a bad
// form fails before any vault is touched.
func validateSetup(setup vaultcrypto.Setup, recoveryPassphrase string, needRecovery bool) error {
	switch setup.Mode {
	case vaultcrypto.Password, vaultcrypto.Either, vaultcrypto.Both:
		if setup.Password == "" {
			return errors.New("Enter a password.")
		}
	case vaultcrypto.SSH:
	default:
		return errors.New("Choose how the vault unlocks: password, SSH key, either, or both.")
	}
	if needRecovery && len(recoveryPassphrase) < minRecoveryPW {
		return fmt.Errorf("The recovery passphrase needs at least %d characters.", minRecoveryPW)
	}
	probe, err := vaultcrypto.NewDataKey()
	if err != nil {
		return err
	}
	if _, err := vaultcrypto.Wrap(probe, setup); err != nil {
		return errors.New("That SSH public key could not be used. Paste the whole line from your .pub file.")
	}
	return nil
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	var b credentialsBody
	if !decode(w, r, &b) {
		return
	}
	if vault.Exists(s.cfg.VaultPath) {
		writeError(w, http.StatusConflict, "A vault already exists here. Unlock it instead.")
		return
	}
	ip := clientIP(r)
	if s.remote {
		if wait := s.limiter.wait(ip); wait > 0 {
			tooMany(w, wait)
			return
		}
		if subtle.ConstantTimeCompare([]byte(b.SetupCode), []byte(s.setupCode)) != 1 {
			s.limiter.fail(ip)
			writeError(w, http.StatusForbidden, "That setup code is not right. It is printed in the server's output when it starts.")
			return
		}
	}
	setup := vaultcrypto.Setup{Mode: b.Mode, Password: b.Password, SSHPublicKey: b.SSHPublicKey}
	if err := validateSetup(setup, b.RecoveryPassphrase, !b.NoRecovery); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	code, err := vault.Create(s.cfg.VaultPath, vault.CreateOptions{Setup: setup, RecoveryPassphrase: b.RecoveryPassphrase, NoRecovery: b.NoRecovery})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The vault could not be created. Check that the vault location is writable.")
		return
	}
	s.limiter.ok(ip)
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCode": code})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, fmt.Sprintf("Too many attempts. Try again in %d seconds.", secs))
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request, sess *session) {
	var b struct {
		Password        string `json:"password"`
		SSHIdentityPath string `json:"sshIdentityPath"`
		SSHPassphrase   string `json:"sshPassphrase"`
	}
	if !decode(w, r, &b) {
		return
	}
	if !vault.Exists(s.cfg.VaultPath) {
		writeError(w, http.StatusNotFound, "There is no vault yet. Create one first.")
		return
	}
	ip := clientIP(r)
	if wait := s.limiter.wait(ip); wait > 0 {
		tooMany(w, wait)
		return
	}
	creds := vault.Creds{Password: b.Password, SSHIdentityPath: strings.TrimSpace(b.SSHIdentityPath)}
	creds.SSHPassphrase = func() ([]byte, error) { return []byte(b.SSHPassphrase), nil }
	v, err := vault.Open(s.cfg.VaultPath, creds)
	if err != nil {
		s.limiter.fail(ip)
		writeError(w, http.StatusUnauthorized, "Could not unlock. Check your password or key and try again.")
		return
	}
	s.limiter.ok(ip)
	s.ensure(w, sess).setVault(v)
	writeJSON(w, http.StatusOK, map[string]any{"unlocked": true})
}

func (s *Server) handleRecover(w http.ResponseWriter, r *http.Request, sess *session) {
	var b struct {
		credentialsBody
		Code                  string `json:"code"`
		Passphrase            string `json:"passphrase"`
		NewRecoveryPassphrase string `json:"newRecoveryPassphrase"`
	}
	if !decode(w, r, &b) {
		return
	}
	// New credentials are validated before the recovery secrets are checked,
	// so a form error can never confirm that the secrets were right.
	setup := vaultcrypto.Setup{Mode: b.Mode, Password: b.Password, SSHPublicKey: b.SSHPublicKey}
	if err := validateSetup(setup, b.NewRecoveryPassphrase, true); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ip := clientIP(r)
	if wait := s.limiter.wait(ip); wait > 0 {
		tooMany(w, wait)
		return
	}
	code, err := vault.Recover(s.cfg.VaultPath, b.Code, b.Passphrase, func() (vault.NewCredentials, error) {
		return vault.NewCredentials{Setup: setup, RecoveryPassphrase: b.NewRecoveryPassphrase}, nil
	})
	if err != nil {
		s.limiter.fail(ip)
		writeError(w, http.StatusUnauthorized, "Recovery failed.")
		return
	}
	s.limiter.ok(ip)
	if sess != nil {
		sess.setVault(nil)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recoveryCode": code})
}

type accountJSON struct {
	ID      int64  `json:"id"`
	Label   string `json:"label"`
	Issuer  string `json:"issuer"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Digits  int    `json:"digits"`
	Code    string `json:"code"`
	Counter uint64 `json:"counter"`
}

func kindName(k migration.Kind) string {
	if k == migration.HOTP {
		return "hotp"
	}
	return "totp"
}

func (s *Server) codeFor(a migration.Account) string {
	if a.Kind == migration.HOTP {
		return otp.HOTP(a.Secret, a.Counter, a.Digits, a.Algorithm)
	}
	return otp.TOTP(a.Secret, s.now(), totpPeriod, a.Digits, a.Algorithm)
}

func (s *Server) handleCodes(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	recs, err := v.Records()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The accounts could not be read from the vault.")
		return
	}
	list := make([]accountJSON, len(recs))
	for i, rec := range recs {
		list[i] = accountJSON{ID: rec.ID, Label: account.Label(rec.Account), Issuer: rec.Issuer, Name: rec.Name,
			Kind: kindName(rec.Kind), Digits: rec.Digits, Code: s.codeFor(rec.Account), Counter: rec.Counter}
	}
	writeJSON(w, http.StatusOK, map[string]any{"secondsLeft": otp.SecondsLeft(s.now(), totpPeriod), "accounts": list})
}

func findRecord(v *vault.Session, r *http.Request) (store.Record, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return store.Record{}, false
	}
	recs, err := v.Records()
	if err != nil {
		return store.Record{}, false
	}
	for _, rec := range recs {
		if rec.ID == id {
			return rec, true
		}
	}
	return store.Record{}, false
}

func (s *Server) handleNext(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	rec, ok := findRecord(v, r)
	if !ok {
		writeError(w, http.StatusNotFound, "That account was not found.")
		return
	}
	if rec.Kind != migration.HOTP {
		writeError(w, http.StatusBadRequest, "Only counter-based accounts have a next code.")
		return
	}
	rec.Counter++
	if err := v.SetCounter(rec.ID, rec.Counter); err != nil {
		writeError(w, http.StatusInternalServerError, "The new counter could not be saved.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"counter": rec.Counter, "code": s.codeFor(rec.Account)})
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	rec, ok := findRecord(v, r)
	if !ok {
		writeError(w, http.StatusNotFound, "That account was not found.")
		return
	}
	data, err := qrcode.PNG(account.URL(rec.Account), 512)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The QR code could not be drawn.")
		return
	}
	if err := v.Log("show_qr", "account="+strconv.FormatInt(rec.ID, 10)); err != nil {
		writeError(w, http.StatusInternalServerError, "The activity log could not be written.")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(data) // the client went away; nothing else to do
}

func (s *Server) handleDetails(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	rec, ok := findRecord(v, r)
	if !ok {
		writeError(w, http.StatusNotFound, "That account was not found.")
		return
	}
	if err := v.Log("reveal", "account="+strconv.FormatInt(rec.ID, 10)); err != nil {
		writeError(w, http.StatusInternalServerError, "The activity log could not be written.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"url": account.URL(rec.Account), "secret": account.Base32(rec.Secret)})
}

func (s *Server) handleDecodeImage(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "That upload is too large. Choose images under 10 MB.")
		return
	}
	texts, problems := []string{}, []string{}
	if r.MultipartForm != nil {
		for _, header := range r.MultipartForm.File["image"] {
			f, err := header.Open()
			if err != nil {
				problems = append(problems, header.Filename+": could not be opened")
				continue
			}
			found, err := qrcode.Read(f, header.Filename)
			_ = f.Close() // read-only upload: a close error is not actionable
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			texts = append(texts, found...)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"texts": texts, "errors": problems})
}

type textsBody struct {
	Texts []string `json:"texts"`
}

func (s *Server) handlePreview(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	var b textsBody
	if !decode(w, r, &b) {
		return
	}
	accounts, warnings, err := source.Preview(b.Texts)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, previewMessage(err))
		return
	}
	recs, err := v.Records()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The accounts could not be read from the vault.")
		return
	}
	saved := map[string]bool{}
	for _, rec := range recs {
		saved[accountKey(rec.Account)] = true
	}
	if warnings == nil {
		warnings = []string{}
	}
	list := make([]map[string]any, len(accounts))
	for i, a := range accounts {
		list[i] = map[string]any{"label": account.Label(a), "kind": kindName(a.Kind), "saved": saved[accountKey(a)]}
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": list, "warnings": warnings})
}

func accountKey(a migration.Account) string {
	return a.Issuer + "\x00" + a.Name + "\x00" + string(a.Secret)
}

func previewMessage(err error) string {
	return "Could not read that as a QR export: " + err.Error()
}

func (s *Server) handleCommit(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	var b textsBody
	if !decode(w, r, &b) {
		return
	}
	accounts, _, err := source.Preview(b.Texts)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, previewMessage(err))
		return
	}
	added, err := v.Import(accounts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The accounts could not be saved.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added})
}

var exportFiles = map[string]string{
	"bitwarden":     "otpmh-bitwarden.json",
	"passwords-csv": "otpmh-passwords.csv",
	"otpauth":       "otpmh-otpauth.txt",
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	var b struct {
		Format  string `json:"format"`
		Confirm bool   `json:"confirm"`
	}
	if !decode(w, r, &b) {
		return
	}
	name, ok := exportFiles[b.Format]
	if !ok {
		writeError(w, http.StatusBadRequest, "Choose an export format: Bitwarden, Passwords app CSV, or otpauth list.")
		return
	}
	if !b.Confirm {
		writeError(w, http.StatusBadRequest, "Exports are not encrypted. Confirm that you want to download your secrets.")
		return
	}
	data, err := v.Export(b.Format)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The export could not be created.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(data) // the client went away; nothing else to do
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request, v *vault.Session) {
	logs, err := v.Logs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "The activity log could not be read.")
		return
	}
	entries := make([]map[string]string, len(logs))
	for i, e := range logs {
		entries[i] = map[string]string{"time": e.Time.Format(time.RFC3339), "action": e.Action, "detail": e.Detail}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}
