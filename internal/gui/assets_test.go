package gui

import (
	"io/fs"
	"net/http"
	"path"
	"regexp"
	"strings"
	"testing"
)

// ownFiles are the interface files written for this project; the vendored
// decoder and font licenses are third-party text and are not scanned.
func ownFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := fs.WalkDir(webFiles, "web", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		switch path.Ext(p) {
		case ".html", ".css", ".js", ".svg":
		default:
			return nil
		}
		if strings.HasPrefix(p, "web/vendor/") {
			return nil
		}
		data, err := fs.ReadFile(webFiles, p)
		files[p] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 8 {
		t.Fatalf("expected the interface files to be embedded, found %d", len(files))
	}
	return files
}

func TestAssets_NoExternalURLs(t *testing.T) {
	url := regexp.MustCompile(`https?://[^\s"'<>)]+`)
	for name, text := range ownFiles(t) {
		for _, m := range url.FindAllString(text, -1) {
			if m == "http://www.w3.org/2000/svg" { // an XML namespace, never fetched
				continue
			}
			t.Errorf("%s references %s; everything must be served from the binary", name, m)
		}
	}
}

func TestAssets_NoGUILabel(t *testing.T) {
	for name, text := range ownFiles(t) {
		if strings.Contains(strings.ToLower(text), "gui") {
			t.Errorf("%s contains the text \"GUI\"", name)
		}
	}
}

func TestAssets_CompatibleWithStrictCSP(t *testing.T) {
	index := ownFiles(t)["web/index.html"]
	if regexp.MustCompile(`(?s)<script[^>]*>[^<]+</script>`).MatchString(index) {
		t.Error("index.html has an inline script, which the Content-Security-Policy blocks")
	}
	if strings.Contains(index, "style=") || strings.Contains(index, "<style") {
		t.Error("index.html has inline styles, which the Content-Security-Policy blocks")
	}
	for name, text := range ownFiles(t) {
		if path.Ext(name) == ".js" && (strings.Contains(text, "innerHTML") || strings.Contains(text, "eval(")) {
			t.Errorf("%s uses innerHTML or eval", name)
		}
	}
}

func TestAssets_ServedWithRightTypes(t *testing.T) {
	s := newLocal(t)
	cases := map[string]string{
		"/":                         "text/html",
		"/app.css":                  "text/css",
		"/app.js":                   "text/javascript",
		"/fonts/bricolage.woff2":    "font/woff2",
		"/fonts/martian-mono.woff2": "font/woff2",
		"/vendor/jsQR.js":           "text/javascript",
		"/icon.svg":                 "image/svg+xml",
	}
	for p, want := range cases {
		rec := do(s, "GET", p, localHost, nil)
		if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), want) || rec.Body.Len() == 0 {
			t.Errorf("%s: status %d type %q len %d, want %s", p, rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len(), want)
		}
	}
}

func TestAssets_LicensesShipWithThirdPartyFiles(t *testing.T) {
	for _, p := range []string{"web/vendor/LICENSE-jsQR.txt", "web/fonts/LICENSE-bricolage.txt", "web/fonts/LICENSE-martian-mono.txt"} {
		if data, err := fs.ReadFile(webFiles, p); err != nil || len(data) == 0 {
			t.Errorf("%s missing: %v", p, err)
		}
	}
}
