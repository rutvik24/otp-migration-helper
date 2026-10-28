package source

import (
	"encoding/base64"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	goqr "github.com/skip2/go-qrcode"
	"google.golang.org/protobuf/encoding/protowire"
)

func link(batchID, size, index int, names ...string) string {
	var b []byte
	for _, n := range names {
		var p []byte
		p = protowire.AppendTag(p, 1, protowire.BytesType)
		p = protowire.AppendBytes(p, []byte("secret-"+n))
		p = protowire.AppendTag(p, 2, protowire.BytesType)
		p = protowire.AppendString(p, n)
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, p)
	}
	for i, v := range []int{size, index, batchID} {
		b = protowire.AppendTag(b, protowire.Number(3+i), protowire.VarintType)
		b = protowire.AppendVarint(b, uint64(v))
	}
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func TestLoad_LinkArg(t *testing.T) {
	accts, warns, err := Load([]string{link(1, 1, 0, "a", "b")}, nil)
	if err != nil || len(accts) != 2 || len(warns) != 0 {
		t.Fatalf("accts=%d warns=%v err=%v", len(accts), warns, err)
	}
}

func TestLoad_ImagePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "q.png")
	if err := goqr.WriteFile(link(1, 1, 0, "a"), goqr.Medium, 400, path); err != nil {
		t.Fatal(err)
	}
	accts, _, err := Load([]string{path}, nil)
	if err != nil || len(accts) != 1 {
		t.Fatalf("accts=%d err=%v", len(accts), err)
	}
}

func TestLoad_StdinLines(t *testing.T) {
	in := strings.NewReader(link(1, 2, 0, "a") + "\n\n" + link(1, 2, 1, "b") + "\n")
	accts, warns, err := Load(nil, in)
	if err != nil || len(accts) != 2 || len(warns) != 0 {
		t.Fatalf("accts=%d warns=%v err=%v", len(accts), warns, err)
	}
}

func TestLoad_MissingBatchWarns(t *testing.T) {
	_, warns, err := Load([]string{link(9, 3, 0, "a"), link(9, 3, 2, "c")}, nil)
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "QR code 2 of 3") {
		t.Fatalf("warns=%v err=%v", warns, err)
	}
}

func TestLoad_DuplicateAccountOnce(t *testing.T) {
	l := link(1, 1, 0, "a")
	accts, _, err := Load([]string{l, l}, nil)
	if err != nil || len(accts) != 1 {
		t.Fatalf("accts=%d err=%v", len(accts), err)
	}
}
