package main

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func testLink(names ...string) string {
	var b []byte
	for _, n := range names {
		var p []byte
		p = protowire.AppendTag(p, 1, protowire.BytesType)
		p = protowire.AppendBytes(p, []byte("12345678901234567890"))
		p = protowire.AppendTag(p, 2, protowire.BytesType)
		p = protowire.AppendString(p, n)
		p = protowire.AppendTag(p, 6, protowire.VarintType)
		p = protowire.AppendVarint(p, 2)
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, p)
	}
	return "otpauth-migration://offline?data=" + url.QueryEscape(base64.StdEncoding.EncodeToString(b))
}

func TestShow_AllPrintsEveryAccountWithQR(t *testing.T) {
	var out strings.Builder
	err := runShow([]string{"--all", testLink("alice", "bob")}, nil, &out)
	if err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"alice", "bob", "otpauth://totp/alice", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "█", "keep these secret"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestShow_NoInputsNoStdinErrors(t *testing.T) {
	var out strings.Builder
	if err := runShow([]string{"--all"}, nil, &out); err == nil {
		t.Error("expected error")
	}
}

func TestUnknownSubcommand(t *testing.T) {
	var out strings.Builder
	if err := run([]string{"bogus"}, nil, &out); err == nil {
		t.Error("expected error")
	}
}

func TestRunLive_NonTTYErrors(t *testing.T) {
	var out strings.Builder
	if err := runLive([]string{"--all", testLink("a")}, nil, &out); err == nil {
		t.Error("expected error")
	}
}

func TestScan_UnsupportedOSMessage(t *testing.T) {
	old := supported
	supported = func() bool { return false }
	defer func() { supported = old }()

	var out strings.Builder
	for _, err := range []error{runScan(nil, strings.NewReader(""), &out), runInstallShortcuts(&out)} {
		if err == nil || !strings.Contains(err.Error(), "only works on macOS") {
			t.Errorf("err=%v", err)
		}
	}
}
