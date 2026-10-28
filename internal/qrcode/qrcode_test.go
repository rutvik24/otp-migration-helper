package qrcode

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	goqr "github.com/skip2/go-qrcode"
)

func TestRender_NotEmpty(t *testing.T) {
	out, err := Render("hello")
	if err != nil || strings.Count(out, "\n") < 5 {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

func TestReadFile_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qr.png")
	if err := goqr.WriteFile("otpauth-migration://offline?data=abc", goqr.Medium, 256, path); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFile(path)
	if err != nil || len(got) != 1 || got[0] != "otpauth-migration://offline?data=abc" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestReadFile_Errors(t *testing.T) {
	dir := t.TempDir()
	notImage := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(notImage, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}

	blank := filepath.Join(dir, "blank.png")
	img := image.NewGray(image.Rect(0, 0, 100, 100))
	for i := range img.Pix {
		img.Pix[i] = 255
	}
	f, err := os.Create(blank)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{filepath.Join(dir, "missing.png"), notImage, blank} {
		_, err := ReadFile(p)
		if err == nil || !strings.Contains(err.Error(), p) {
			t.Errorf("%s: err=%v, want error naming the path", p, err)
		}
	}
}

func TestRead_FromBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qr.png")
	if err := goqr.WriteFile("hello bytes", goqr.Medium, 256, path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(bytes.NewReader(data), "upload.png")
	if err != nil || len(got) != 1 || got[0] != "hello bytes" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestRead_NotAnImageNamesIt(t *testing.T) {
	_, err := Read(strings.NewReader("definitely not an image"), "notes.txt")
	if err == nil || !strings.Contains(err.Error(), "notes.txt") {
		t.Errorf("err: %v", err)
	}
}

func TestPNG_DecodesBack(t *testing.T) {
	data, err := PNG("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ", 256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Read(bytes.NewReader(data), "qr.png")
	if err != nil || len(got) != 1 || got[0] != "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}
