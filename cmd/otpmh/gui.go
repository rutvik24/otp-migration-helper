package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rutvik24/otp-migration-helper/internal/gui"
	"github.com/rutvik24/otp-migration-helper/internal/vault"
)

const defaultServerPort = "8080"

// hostList collects repeated --allowed-host flags.
type hostList []string

func (h *hostList) String() string     { return strings.Join(*h, ",") }
func (h *hostList) Set(v string) error { *h = append(*h, v); return nil }

func envBool(env func(string) string, name string) bool {
	v := strings.ToLower(env(name))
	return v == "1" || v == "true" || v == "yes"
}

func splitHosts(csv string) []string {
	var hosts []string
	for _, h := range strings.Split(csv, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// guiConfig reads flags, falling back to OTPMH_* environment variables (never for secrets).
func guiConfig(args []string, env func(string) string, out io.Writer) (gui.Config, bool, error) {
	fs := flag.NewFlagSet("gui", flag.ContinueOnError)
	fs.SetOutput(out)
	vaultPath := fs.String("vault-path", env("OTPMH_VAULT_PATH"), "vault file (default: <user config dir>/otpmh/vault.db)")
	port := fs.Int("port", 0, "local port (default: a free one)")
	noOpen := fs.Bool("no-open", false, "do not open the browser")
	listen := fs.String("listen", env("OTPMH_LISTEN"), "server mode: address to listen on, for example :8080")
	cert := fs.String("tls-cert", env("OTPMH_TLS_CERT"), "server mode: TLS certificate file")
	key := fs.String("tls-key", env("OTPMH_TLS_KEY"), "server mode: TLS key file")
	insecure := fs.Bool("insecure-http", envBool(env, "OTPMH_INSECURE_HTTP"), "server mode: allow plain HTTP (TLS handled by a proxy, or published on loopback only)")
	var hosts hostList
	fs.Var(&hosts, "allowed-host", "server mode: accepted Host name (repeatable)")
	if err := fs.Parse(args); err != nil {
		return gui.Config{}, false, err
	}
	if len(hosts) == 0 {
		hosts = splitHosts(env("OTPMH_ALLOWED_HOSTS"))
	}

	path, err := (&vaultFlags{path: *vaultPath}).resolvePath()
	if err != nil {
		return gui.Config{}, false, err
	}
	return gui.Config{
		VaultPath: path, Port: *port, Listen: *listen, TLSCert: *cert, TLSKey: *key,
		AllowedHosts: hosts, InsecureHTTP: *insecure,
	}, *noOpen, nil
}

func runGui(args []string, stdin io.Reader, out io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runGuiContext(ctx, args, os.Getenv, out)
}

func runGuiContext(ctx context.Context, args []string, env func(string) string, out io.Writer) error {
	cfg, noOpen, err := guiConfig(args, env, out)
	if err != nil {
		return err
	}
	srv, err := gui.New(cfg)
	if err != nil {
		return err
	}

	if cfg.Listen != "" {
		say(out, "otpmh is listening on %s\n", cfg.Listen)
		if !vault.Exists(cfg.VaultPath) {
			say(out, "No vault yet. Open the page and use this setup code to create it: %s\n", srv.SetupCode())
		}
	}
	return srv.Run(ctx, func(link string) {
		sayln(out, "otpmh is running. If your browser does not open, use this link:")
		sayln(out, link)
		if !noOpen {
			if err := openBrowser(link); err != nil {
				sayln(out, "Could not open the browser:", err)
			}
		}
	})
}

func openBrowser(link string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", link)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	default:
		cmd = exec.Command("xdg-open", link)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // reap the helper process; its exit status does not matter
	return nil
}

// runHealthcheck is what the container's HEALTHCHECK runs: the image has no
// shell or curl, so the binary probes itself.
func runHealthcheck(args []string, env func(string) string, out io.Writer) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(out)
	scheme := "http"
	if env("OTPMH_TLS_CERT") != "" {
		scheme = "https"
	}
	port := defaultServerPort
	if _, p, err := net.SplitHostPort(env("OTPMH_LISTEN")); err == nil && p != "" {
		port = p
	}
	target := fs.String("url", scheme+"://127.0.0.1:"+port+"/healthz", "address to probe")
	if err := fs.Parse(args); err != nil {
		return err
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
		// Only ever used against this machine's own loopback address.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Get(*target)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: %s", resp.Status)
	}
	return nil
}
