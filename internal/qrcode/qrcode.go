// Package qrcode renders QR codes to the terminal and reads them from images.
package qrcode

import (
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"os"

	"github.com/makiuchi-d/gozxing"
	multiqr "github.com/makiuchi-d/gozxing/multi/qrcode"
	goqr "github.com/skip2/go-qrcode"
)

// Render returns the QR code as block characters for a terminal.
func Render(text string) (string, error) {
	q, err := goqr.New(text, goqr.Medium)
	if err != nil {
		return "", err
	}
	return q.ToSmallString(false), nil
}

// PNG renders the QR code as a PNG image of the given size in pixels.
func PNG(text string, size int) ([]byte, error) {
	return goqr.Encode(text, goqr.Medium, size)
}

// ReadFile returns the text of every QR code found in the image at path.
func ReadFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only file: a close error is not actionable
	return Read(f, path)
}

// Read returns the text of every QR code found in the image; name is only
// used in error messages.
func Read(r io.Reader, name string) ([]string, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return nil, fmt.Errorf("%s: not a readable image: %w", name, err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	results, err := multiqr.NewQRCodeMultiReader().DecodeMultiple(bmp, nil)
	if err != nil || len(results) == 0 {
		return nil, fmt.Errorf("%s: no QR code found", name)
	}
	texts := make([]string, len(results))
	for i, r := range results {
		texts[i] = r.GetText()
	}
	return texts, nil
}
