// Package source gathers accounts from migration links, otpauth:// URIs and
// QR images. Inputs may be mixed in any order.
package source

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
)

const (
	migrationPrefix = "otpauth-migration://"
	uriPrefix       = "otpauth://"
)

// Load turns every input into accounts. An input is a migration link, an
// otpauth:// URI (both are what a QR code decodes to), or the path of a QR
// image. With no inputs, the same kinds are read from stdin, one per line.
// Warnings report batches whose QR codes were not all provided.
func Load(inputs []string, stdin io.Reader) ([]migration.Account, []string, error) {
	if len(inputs) == 0 {
		var err error
		if inputs, err = readLines(stdin); err != nil {
			return nil, nil, err
		}
	}
	if len(inputs) == 0 {
		return nil, nil, errors.New("no migration links, otpauth URIs or QR images provided")
	}

	texts, err := resolve(inputs)
	if err != nil {
		return nil, nil, err
	}
	return collect(texts)
}

// Preview decodes already-read QR texts (migration links and otpauth URIs)
// into accounts, merging batches and reporting missing QR codes. It never
// reads files, so it is safe to feed with text from a network client.
func Preview(texts []string) ([]migration.Account, []string, error) {
	if len(texts) == 0 {
		return nil, nil, errors.New("no QR text provided")
	}
	return collect(texts)
}

func collect(texts []string) ([]migration.Account, []string, error) {
	c := collector{seen: map[string]bool{}, batches: map[int32]*batchState{}}
	for _, text := range texts {
		if err := c.add(text); err != nil {
			return nil, nil, err
		}
	}
	return c.accounts, missingWarnings(c.batches), nil
}

func readLines(r io.Reader) ([]string, error) {
	if r == nil {
		return nil, nil
	}
	var lines []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

// resolve returns the decoded text of every input: text inputs as they are,
// image inputs by reading the QR codes in them.
func resolve(inputs []string) ([]string, error) {
	var texts []string
	for _, in := range inputs {
		in = strings.TrimSpace(in)
		if strings.HasPrefix(in, migrationPrefix) || strings.HasPrefix(in, uriPrefix) {
			texts = append(texts, in)
			continue
		}
		if _, err := os.Stat(in); err != nil {
			return nil, fmt.Errorf("%q is not an otpauth link or an existing QR image file", in)
		}
		found, err := qrcode.ReadFile(in)
		if err != nil {
			return nil, err
		}
		texts = append(texts, found...)
	}
	return texts, nil
}

type batchState struct {
	size    int32
	indexes map[int32]bool
}

type collector struct {
	accounts []migration.Account
	seen     map[string]bool
	batches  map[int32]*batchState
}

func (c *collector) add(text string) error {
	text = strings.TrimSpace(text)
	switch {
	case strings.HasPrefix(text, migrationPrefix):
		batch, err := migration.Decode(text)
		if err != nil {
			return err
		}
		st := c.batches[batch.BatchID]
		if st == nil {
			st = &batchState{size: batch.Size, indexes: map[int32]bool{}}
			c.batches[batch.BatchID] = st
		}
		st.indexes[batch.Index] = true
		for _, a := range batch.Accounts {
			c.addAccount(a)
		}
	case strings.HasPrefix(text, uriPrefix):
		a, err := migration.DecodeURI(text)
		if err != nil {
			return err
		}
		c.addAccount(a)
	default:
		return fmt.Errorf("unsupported QR code content (not an otpauth link): %.40q", text)
	}
	return nil
}

func (c *collector) addAccount(a migration.Account) {
	key := a.Issuer + "\x00" + a.Name + "\x00" + string(a.Secret)
	if !c.seen[key] {
		c.seen[key] = true
		c.accounts = append(c.accounts, a)
	}
}

func missingWarnings(batches map[int32]*batchState) []string {
	ids := make([]int, 0, len(batches))
	for id := range batches {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	var warns []string
	for _, id := range ids {
		st := batches[int32(id)]
		for i := int32(0); i < st.size; i++ {
			if !st.indexes[i] {
				warns = append(warns, fmt.Sprintf("export %d is missing QR code %d of %d", id, i+1, st.size))
			}
		}
	}
	return warns
}
