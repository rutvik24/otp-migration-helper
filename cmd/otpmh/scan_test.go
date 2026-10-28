package main

import (
	"bufio"
	"encoding/base64"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	goqr "github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/encoding/protowire"
)

// batchLink is one QR code of a multi-code export: index of size.
func batchLink(batchID, size, index int, name string) string {
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

func TestInterpretShortcutOutput_Text(t *testing.T) {
	link := batchLink(1, 1, 0, "a")
	got, err := interpretShortcutOutput(link + "\n")
	if err != nil || len(got) != 1 || got[0] != link {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestInterpretShortcutOutput_SeveralCodesOnSeveralLines(t *testing.T) {
	a, b := batchLink(1, 2, 0, "a"), "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ"
	got, err := interpretShortcutOutput(a + "\n\n  " + b + "  \n" + a)
	if err != nil || len(got) != 2 {
		t.Fatalf("duplicates and blanks should be dropped: got=%v err=%v", got, err)
	}
}

func TestInterpretShortcutOutput_ChosenImageFile(t *testing.T) {
	link := batchLink(1, 1, 0, "a")
	for _, name := range []string{"qr.png", "My QR code.png"} { // the Finder path may contain spaces
		path := filepath.Join(t.TempDir(), name)
		if err := goqr.WriteFile(link, goqr.Medium, 400, path); err != nil {
			t.Fatal(err)
		}
		got, err := interpretShortcutOutput(path + "\n")
		if err != nil || len(got) != 1 || got[0] != link {
			t.Errorf("%s: got=%v err=%v", name, got, err)
		}
	}
}

func TestInterpretShortcutOutput_NotAQRCode(t *testing.T) {
	for _, in := range []string{"hello world", "/no/such/file.png", "https://example.com"} {
		if _, err := interpretShortcutOutput(in); err == nil || !strings.Contains(err.Error(), "not a QR code") {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func TestScanAll_ReadsEveryCodeOfAnExport(t *testing.T) {
	queue := [][]string{{batchLink(7, 2, 0, "a")}, {batchLink(7, 2, 1, "b")}}
	scan := func() ([]string, error) {
		next := queue[0]
		queue = queue[1:]
		return next, nil
	}
	var out strings.Builder
	links, err := scanAll(scan, bufio.NewReader(strings.NewReader("\n")), &out)
	if err != nil || len(links) != 2 {
		t.Fatalf("links=%d err=%v", len(links), err)
	}
	if !strings.Contains(out.String(), "missing QR code 2 of 2") {
		t.Errorf("should say what is missing after the first code:\n%s", out.String())
	}
}

func TestScanAll_CanContinueWithWhatWasRead(t *testing.T) {
	scan := func() ([]string, error) { return []string{batchLink(7, 3, 0, "a")}, nil }
	links, err := scanAll(scan, bufio.NewReader(strings.NewReader("q\n")), &strings.Builder{})
	if err != nil || len(links) != 1 {
		t.Fatalf("links=%d err=%v", len(links), err)
	}
}

func isWindows() bool { return runtime.GOOS == "windows" }
