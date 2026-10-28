package gui

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
)

const (
	pw      = "correct horse"
	recPass = "recovery-passphrase-1"
	// secret "12345678901234567890"
	totpURI = "otpauth://totp/Acme:alice@x.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Acme"
	hotpURI = "otpauth://hotp/Hotp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=4"
)

type client struct {
	t      *testing.T
	s      *Server
	cookie *http.Cookie
}

func newClient(t *testing.T) *client {
	t.Helper()
	s := newLocal(t)
	s.now = func() time.Time { return time.Unix(59, 0) }
	return &client{t: t, s: s, cookie: launch(t, s)}
}

func (c *client) req(method, path string, body any) *httptest.ResponseRecorder {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			c.t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Host = localHost
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set(csrfHeader, csrfValue)
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	rec := httptest.NewRecorder()
	c.s.Handler().ServeHTTP(rec, req)
	return rec
}

func (c *client) json(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	rec := c.req(method, path, body)
	var out map[string]any
	if rec.Body.Len() > 0 && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			c.t.Fatalf("%s %s: bad JSON %q: %v", method, path, rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

func (c *client) createAndUnlock() {
	c.t.Helper()
	code, out := c.json("POST", "/api/vault", map[string]any{"mode": "password", "password": pw, "recoveryPassphrase": recPass})
	if code != 200 || out["recoveryCode"] == "" {
		c.t.Fatalf("create: %d %v", code, out)
	}
	if code, out := c.json("POST", "/api/unlock", map[string]any{"password": pw}); code != 200 {
		c.t.Fatalf("unlock: %d %v", code, out)
	}
}

func (c *client) verify() {
	c.t.Helper()
	if code, out := c.json("POST", "/api/reauth", map[string]any{"password": pw}); code != 200 {
		c.t.Fatalf("reauth: %d %v", code, out)
	}
}

func (c *client) commit(texts ...string) {
	c.t.Helper()
	if code, out := c.json("POST", "/api/import/commit", map[string]any{"texts": texts}); code != 200 {
		c.t.Fatalf("commit: %d %v", code, out)
	}
}

func accountsOf(out map[string]any) []map[string]any {
	var list []map[string]any
	for _, a := range out["accounts"].([]any) {
		list = append(list, a.(map[string]any))
	}
	return list
}

func TestFlow_CreateUnlockImportCodes(t *testing.T) {
	c := newClient(t)
	if _, st := c.json("GET", "/api/status", nil); st["exists"] != false || st["unlocked"] != false {
		t.Fatalf("fresh status: %v", st)
	}
	c.createAndUnlock()
	if _, st := c.json("GET", "/api/status", nil); st["exists"] != true || st["unlocked"] != true || st["mode"] != "password" {
		t.Fatalf("status: %v", st)
	}
	c.commit(totpURI)

	code, out := c.json("GET", "/api/codes", nil)
	if code != 200 || out["secondsLeft"] != float64(1) {
		t.Fatalf("codes: %d %v", code, out)
	}
	a := accountsOf(out)[0]
	if a["code"] != "287082" || a["label"] != "Acme:alice@x.com" || a["kind"] != "totp" {
		t.Errorf("account: %v", a)
	}
	if _, has := a["secret"]; has {
		t.Error("codes must not include the secret")
	}
}

func TestCodes_Locked401(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.json("POST", "/api/lock", nil)
	for _, path := range []string{"/api/codes", "/api/log", "/api/accounts/1/qr.png", "/api/accounts/1/details"} {
		if rec := c.req("GET", path, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", path, rec.Code)
		}
	}
}

func TestUnlock_WrongPasswordGeneric(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.json("POST", "/api/lock", nil)
	code, out := c.json("POST", "/api/unlock", map[string]any{"password": "wrong"})
	if code != http.StatusUnauthorized || strings.Contains(out["error"].(string), "wrong") {
		t.Errorf("%d %v", code, out)
	}
}

func TestUnlock_RateLimited(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.json("POST", "/api/lock", nil)
	for i := 0; i < 3; i++ {
		c.json("POST", "/api/unlock", map[string]any{"password": "wrong"})
	}
	rec := c.req("POST", "/api/unlock", map[string]any{"password": pw})
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("status %d retry-after %q, want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
}

func TestCreate_RemoteNeedsSetupCode(t *testing.T) {
	s, err := New(Config{VaultPath: filepath.Join(t.TempDir(), "v.db"), Listen: ":8080", InsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.sessions.closeAll)
	c := &client{t: t, s: s}
	body := map[string]any{"mode": "password", "password": pw, "recoveryPassphrase": recPass}
	if code, _ := c.json("POST", "/api/vault", body); code != http.StatusForbidden {
		t.Errorf("without setup code: %d, want 403", code)
	}
	body["setupCode"] = s.SetupCode()
	if code, out := c.json("POST", "/api/vault", body); code != 200 {
		t.Errorf("with setup code: %d %v", code, out)
	}
	// Server mode needs no launch cookie; unlocking issues one.
	req := httptest.NewRequest("POST", "/api/unlock", strings.NewReader(`{"password":"`+pw+`"}`))
	req.Host, req.RemoteAddr = "x:8080", "10.0.0.2:1"
	req.Header.Set(csrfHeader, csrfValue)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 || len(rec.Result().Cookies()) == 0 {
		t.Errorf("remote unlock: %d cookies=%v", rec.Code, rec.Result().Cookies())
	}
}

func migrationLink(batchID, size, index int, name string) string {
	var p []byte
	p = protowire.AppendTag(p, 1, protowire.BytesType)
	p = protowire.AppendBytes(p, []byte("12345678901234567890"))
	p = protowire.AppendTag(p, 2, protowire.BytesType)
	p = protowire.AppendString(p, name)
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, p)
	for i, v := range []int{size, index, batchID} {
		b = protowire.AppendTag(b, protowire.Number(3+i), protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(v))
	}
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func TestImportPreview_WarnsOnMissingBatch(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	code, out := c.json("POST", "/api/import/preview", map[string]any{"texts": []string{migrationLink(9, 3, 0, "a"), totpURI}})
	if code != 200 || len(accountsOf(out)) != 2 || len(out["warnings"].([]any)) != 2 {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := c.json("POST", "/api/import/preview", map[string]any{"texts": []string{"hello"}}); code != http.StatusUnprocessableEntity || out["error"] == "" {
		t.Errorf("garbage: %d %v", code, out)
	}
}

func TestImportPreview_EmptyWarningsIsAListNotNull(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	rec := c.req("POST", "/api/import/preview", map[string]any{"texts": []string{totpURI}})
	if !strings.Contains(rec.Body.String(), `"warnings":[]`) {
		t.Errorf("warnings must be an empty list: %s", rec.Body.String())
	}
}

func TestImportCommit_DedupesAndSaves(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	_, first := c.json("POST", "/api/import/commit", map[string]any{"texts": []string{totpURI, hotpURI}})
	_, second := c.json("POST", "/api/import/commit", map[string]any{"texts": []string{totpURI}})
	if first["added"] != float64(2) || second["added"] != float64(0) {
		t.Errorf("added: %v then %v", first["added"], second["added"])
	}
	_, preview := c.json("POST", "/api/import/preview", map[string]any{"texts": []string{totpURI}})
	if accountsOf(preview)[0]["saved"] != true {
		t.Errorf("preview should flag already-saved accounts: %v", preview)
	}
}

func multipartImage(t *testing.T, files map[string][]byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for name, data := range files {
		part, err := w.CreateFormFile("image", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf, w.FormDataContentType()
}

func (c *client) upload(files map[string][]byte) (int, map[string]any) {
	c.t.Helper()
	body, ctype := multipartImage(c.t, files)
	req := httptest.NewRequest("POST", "/api/decode-image", body)
	req.Host, req.RemoteAddr = localHost, "10.0.0.1:5555"
	req.Header.Set(csrfHeader, csrfValue)
	req.Header.Set("Content-Type", ctype)
	req.AddCookie(c.cookie)
	rec := httptest.NewRecorder()
	c.s.Handler().ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		c.t.Fatalf("bad JSON %q", rec.Body.String())
	}
	return rec.Code, out
}

func TestDecodeImage_ReturnsText(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	png, err := qrcode.PNG(totpURI, 400)
	if err != nil {
		t.Fatal(err)
	}
	code, out := c.upload(map[string][]byte{"a.png": png})
	texts := out["texts"].([]any)
	if code != 200 || len(texts) != 1 || texts[0] != totpURI {
		t.Errorf("%d %v", code, out)
	}
}

func TestDecodeImage_NotImageErrors(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	code, out := c.upload(map[string][]byte{"notes.txt": []byte("hello")})
	errs, _ := out["errors"].([]any)
	if code != 200 || len(out["texts"].([]any)) != 0 || len(errs) != 1 || !strings.Contains(errs[0].(string), "notes.txt") {
		t.Errorf("%d %v", code, out)
	}
}

func TestExport_RequiresConfirm(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.commit(totpURI)
	c.verify()
	if rec := c.req("POST", "/api/export", map[string]any{"format": "bitwarden"}); rec.Code != http.StatusBadRequest {
		t.Errorf("without confirm: %d", rec.Code)
	}
	rec := c.req("POST", "/api/export", map[string]any{"format": "bitwarden", "confirm": true})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "otpauth://totp/Acme:alice") || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("%d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if rec := c.req("POST", "/api/export", map[string]any{"format": "nope", "confirm": true}); rec.Code != http.StatusBadRequest {
		t.Errorf("bad format: %d", rec.Code)
	}
}

func TestHotpNext_Persists(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.commit(hotpURI)
	_, out := c.json("GET", "/api/codes", nil)
	hotp := accountsOf(out)[0]
	if hotp["counter"] != float64(4) || hotp["kind"] != "hotp" {
		t.Fatalf("hotp: %v", hotp)
	}
	path := "/api/accounts/" + itoa(hotp["id"]) + "/next"
	if code, out := c.json("POST", path, nil); code != 200 || out["counter"] != float64(5) {
		t.Fatalf("next: %d %v", code, out)
	}
	c.json("POST", "/api/lock", nil)
	c.json("POST", "/api/unlock", map[string]any{"password": pw})
	_, out = c.json("GET", "/api/codes", nil)
	if accountsOf(out)[0]["counter"] != float64(5) {
		t.Errorf("counter did not persist: %v", accountsOf(out)[0])
	}
}

func itoa(v any) string { return strconv.Itoa(int(v.(float64))) }

func TestRecover_RotatesAndOldPasswordFails(t *testing.T) {
	c := newClient(t)
	_, created := c.json("POST", "/api/vault", map[string]any{"mode": "password", "password": pw, "recoveryPassphrase": recPass})
	recoveryCode := created["recoveryCode"].(string)

	body := map[string]any{"code": recoveryCode, "passphrase": recPass, "mode": "password", "password": "new password", "newRecoveryPassphrase": "new-recovery-pass-2"}
	code, out := c.json("POST", "/api/recover", body)
	if code != 200 || out["recoveryCode"] == "" || out["recoveryCode"] == recoveryCode {
		t.Fatalf("recover: %d %v", code, out)
	}
	if code, _ := c.json("POST", "/api/unlock", map[string]any{"password": pw}); code != http.StatusUnauthorized {
		t.Error("old password still works")
	}
	if code, _ := c.json("POST", "/api/unlock", map[string]any{"password": "new password"}); code != 200 {
		t.Error("new password does not work")
	}
}

func TestRecover_WrongSecretsAreGenericAndBadInputDoesNotLeak(t *testing.T) {
	c := newClient(t)
	_, created := c.json("POST", "/api/vault", map[string]any{"mode": "password", "password": pw, "recoveryPassphrase": recPass})
	good := created["recoveryCode"].(string)

	wrong := map[string]any{"code": "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", "passphrase": recPass, "mode": "password", "password": "x1", "newRecoveryPassphrase": "new-recovery-pass-2"}
	code, out := c.json("POST", "/api/recover", wrong)
	if code != http.StatusUnauthorized || out["error"] != "Recovery failed." {
		t.Errorf("wrong code: %d %v", code, out)
	}
	// Right secrets but unusable new credentials must fail validation the same way
	// whether or not the secrets are right, so it cannot confirm them.
	bad := map[string]any{"code": good, "passphrase": recPass, "mode": "password", "password": "", "newRecoveryPassphrase": "short"}
	code1, out1 := c.json("POST", "/api/recover", bad)
	bad["code"] = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"
	code2, out2 := c.json("POST", "/api/recover", bad)
	if code1 != code2 || out1["error"] != out2["error"] {
		t.Errorf("validation leaks: %d %v vs %d %v", code1, out1, code2, out2)
	}
}

func TestDetails_ReturnsSecretOnlyWhenUnlocked(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.commit(totpURI)
	_, codes := c.json("GET", "/api/codes", nil)
	id := itoa(accountsOf(codes)[0]["id"])
	c.verify()
	code, out := c.json("GET", "/api/accounts/"+id+"/details", nil)
	if code != 200 || out["secret"] != "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" || !strings.HasPrefix(out["url"].(string), "otpauth://totp/Acme:alice@x.com") {
		t.Errorf("%d %v", code, out)
	}
	rec := c.req("GET", "/api/accounts/"+id+"/qr.png", nil)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("qr: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if texts, err := qrcode.Read(rec.Body, "qr.png"); err != nil || len(texts) != 1 || !strings.HasPrefix(texts[0], "otpauth://totp/") {
		t.Errorf("qr content: %v %v", texts, err)
	}
}

func TestLog_HasNoSecrets(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.commit(totpURI)
	c.verify()
	c.json("POST", "/api/export", map[string]any{"format": "otpauth", "confirm": true})
	rec := c.req("GET", "/api/log", nil)
	body := rec.Body.String()
	for _, secret := range []string{pw, recPass, "GEZDGNBVGY3TQOJQ", "12345678901234567890"} {
		if strings.Contains(body, secret) {
			t.Errorf("log leaks %q", secret)
		}
	}
	for _, action := range []string{"create", "unlock", "import", "export"} {
		if !strings.Contains(body, action) {
			t.Errorf("log missing %q: %s", action, body)
		}
	}
}

func TestSensitive_RequiresReauth(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	c.commit(totpURI)
	_, codes := c.json("GET", "/api/codes", nil)
	id := itoa(accountsOf(codes)[0]["id"])
	sensitive := func() []int {
		return []int{
			c.req("GET", "/api/accounts/"+id+"/qr.png", nil).Code,
			c.req("GET", "/api/accounts/"+id+"/details", nil).Code,
			c.req("POST", "/api/export", map[string]any{"format": "otpauth", "confirm": true}).Code,
		}
	}
	for i, code := range sensitive() {
		if code != http.StatusForbidden {
			t.Errorf("endpoint %d before verifying: %d, want 403", i, code)
		}
	}
	_, out := c.json("GET", "/api/accounts/"+id+"/details", nil)
	if out["reauth"] != true {
		t.Errorf("403 must say reauth is needed: %v", out)
	}

	if code, _ := c.json("POST", "/api/reauth", map[string]any{"password": "wrong"}); code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d, want 401", code)
	}
	if got := sensitive(); got[0] != 403 {
		t.Errorf("a failed verification must not unlock anything: %v", got)
	}

	c.verify()
	for i, code := range sensitive() {
		if code != http.StatusOK {
			t.Errorf("endpoint %d after verifying: %d, want 200", i, code)
		}
	}

	// The verification expires after two minutes.
	c.s.now = func() time.Time { return time.Unix(59, 0).Add(verifyWindow + time.Second) }
	for i, code := range sensitive() {
		if code != http.StatusForbidden {
			t.Errorf("endpoint %d after expiry: %d, want 403", i, code)
		}
	}

	// Locking and unlocking again also requires a fresh verification.
	c.s.now = func() time.Time { return time.Unix(59, 0) }
	c.verify()
	c.json("POST", "/api/lock", nil)
	c.json("POST", "/api/unlock", map[string]any{"password": pw})
	if got := sensitive(); got[1] != 403 {
		t.Errorf("verification must not survive a lock: %v", got)
	}
}

func TestReauth_RateLimitedAndLogged(t *testing.T) {
	c := newClient(t)
	c.createAndUnlock()
	for i := 0; i < 3; i++ {
		c.json("POST", "/api/reauth", map[string]any{"password": "wrong"})
	}
	if rec := c.req("POST", "/api/reauth", map[string]any{"password": pw}); rec.Code != http.StatusTooManyRequests {
		t.Errorf("status %d, want 429", rec.Code)
	}
	c.s.now = func() time.Time { return time.Unix(59, 0).Add(time.Minute) }
	c.s.limiter.now = c.s.now
	c.verify()
	log := c.req("GET", "/api/log", nil).Body.String()
	for _, action := range []string{"verify_failed", `"verify"`} {
		if !strings.Contains(log, action) {
			t.Errorf("log missing %s: %s", action, log)
		}
	}
}

func sshKeyPair(t *testing.T, passphrase string) (publicLine, privateText string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub)), string(pem.EncodeToMemory(block))
}

func TestUnlock_WithUploadedKeyText(t *testing.T) {
	pub, private := sshKeyPair(t, "key-pass")
	c := newClient(t)
	if code, out := c.json("POST", "/api/vault", map[string]any{"mode": "both", "password": pw, "sshPublicKey": pub, "noRecovery": true}); code != 200 {
		t.Fatalf("create: %d %v", code, out)
	}
	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"key and passphrase and password", map[string]any{"password": pw, "sshPrivateKey": private, "sshPassphrase": "key-pass"}, 200},
		{"windows line endings", map[string]any{"password": pw, "sshPrivateKey": strings.ReplaceAll(private, "\n", "\r\n"), "sshPassphrase": "key-pass"}, 200},
		{"missing passphrase", map[string]any{"password": pw, "sshPrivateKey": private}, 401},
		{"missing key", map[string]any{"password": pw}, 401},
		{"a server path is no longer read", map[string]any{"password": pw, "sshIdentityPath": "/etc/hostname"}, 401},
	}
	for _, tc := range cases {
		c.s.limiter.ok("10.0.0.1") // keep the rate limit out of this table
		c.json("POST", "/api/lock", nil)
		if code, out := c.json("POST", "/api/unlock", tc.body); code != tc.want {
			t.Errorf("%s: %d %v, want %d", tc.name, code, out, tc.want)
		}
	}
}
