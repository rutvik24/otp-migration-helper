package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestGui_FlagParsingAndEnv(t *testing.T) {
	env := envOf(map[string]string{
		"OTPMH_LISTEN": ":9090", "OTPMH_INSECURE_HTTP": "true", "OTPMH_VAULT_PATH": "/data/vault.db",
		"OTPMH_ALLOWED_HOSTS": "a.example, b.example",
	})
	cfg, noOpen, err := guiConfig(nil, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":9090" || !cfg.InsecureHTTP || cfg.VaultPath != "/data/vault.db" || len(cfg.AllowedHosts) != 2 || cfg.AllowedHosts[1] != "b.example" || noOpen {
		t.Errorf("env config: %+v noOpen=%v", cfg, noOpen)
	}

	cfg, noOpen, err = guiConfig([]string{"--listen", ":1234", "--vault-path", "/x.db", "--no-open", "--allowed-host", "c.example", "--port", "5555"}, env, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":1234" || cfg.VaultPath != "/x.db" || !noOpen || cfg.Port != 5555 || len(cfg.AllowedHosts) != 1 || cfg.AllowedHosts[0] != "c.example" {
		t.Errorf("flags should win over env: %+v", cfg)
	}
}

func TestGui_RemotePlainHTTPRefused(t *testing.T) {
	var out strings.Builder
	err := runGuiContext(context.Background(), []string{"--listen", "127.0.0.1:0", "--vault-path", filepath.Join(t.TempDir(), "v.db"), "--no-open"}, envOf(nil), &out)
	if err == nil || !strings.Contains(err.Error(), "insecure-http") {
		t.Errorf("err: %v", err)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

func TestGui_StartsAndServesHealthz(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- runGuiContext(ctx, []string{"--port", "0", "--no-open", "--vault-path", filepath.Join(t.TempDir(), "v.db")}, envOf(nil), out)
	}()

	re := regexp.MustCompile(`http://127\.0\.0\.1:(\d+)/\?t=[0-9a-f]+`)
	var link string
	for i := 0; i < 100 && link == ""; i++ {
		link = re.FindString(out.String())
		time.Sleep(20 * time.Millisecond)
	}
	if link == "" {
		t.Fatalf("no launch link printed: %q", out.String())
	}
	port := re.FindStringSubmatch(link)[1]
	resp, err := http.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != "ok" {
		t.Errorf("healthz: %d %q", resp.StatusCode, body)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && err != context.Canceled {
			t.Errorf("shutdown error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("server did not stop")
	}
}

func TestHealthcheck_OKAndFail(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok\n")) }))
	defer ok.Close()
	if err := runHealthcheck([]string{"--url", ok.URL}, envOf(nil), io.Discard); err != nil {
		t.Errorf("healthy: %v", err)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 500) }))
	defer bad.Close()
	if err := runHealthcheck([]string{"--url", bad.URL}, envOf(nil), io.Discard); err == nil {
		t.Error("unhealthy should fail")
	}
	if err := runHealthcheck([]string{"--url", "http://127.0.0.1:1"}, envOf(nil), io.Discard); err == nil {
		t.Error("unreachable should fail")
	}
}
