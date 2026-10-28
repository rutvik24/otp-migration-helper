// Package source gathers accounts from links, QR images or stdin.
package source

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rutvik24/otp-migration-helper/internal/migration"
	"github.com/rutvik24/otp-migration-helper/internal/qrcode"
)

const linkPrefix = "otpauth-migration://"

// Load decodes every input (a migration link or a QR image path). With no
// inputs it reads one link per line from stdin. Warnings report batches
// whose QR codes were not all provided.
func Load(inputs []string, stdin io.Reader) ([]migration.Account, []string, error) {
	links, err := collectLinks(inputs, stdin)
	if err != nil {
		return nil, nil, err
	}
	if len(links) == 0 {
		return nil, nil, errors.New("no migration links or QR images provided")
	}

	var accounts []migration.Account
	seen := map[string]bool{}
	batches := map[int32]*batchState{}
	for _, l := range links {
		batch, err := migration.Decode(l)
		if err != nil {
			return nil, nil, err
		}
		st := batches[batch.BatchID]
		if st == nil {
			st = &batchState{size: batch.Size, indexes: map[int32]bool{}}
			batches[batch.BatchID] = st
		}
		st.indexes[batch.Index] = true
		for _, a := range batch.Accounts {
			key := a.Issuer + "\x00" + a.Name + "\x00" + string(a.Secret)
			if !seen[key] {
				seen[key] = true
				accounts = append(accounts, a)
			}
		}
	}
	return accounts, missingWarnings(batches), nil
}

type batchState struct {
	size    int32
	indexes map[int32]bool
}

func collectLinks(inputs []string, stdin io.Reader) ([]string, error) {
	var links []string
	if len(inputs) == 0 {
		if stdin == nil {
			return nil, nil
		}
		sc := bufio.NewScanner(stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				links = append(links, line)
			}
		}
		return links, sc.Err()
	}
	for _, in := range inputs {
		if strings.HasPrefix(in, linkPrefix) {
			links = append(links, in)
			continue
		}
		texts, err := qrcode.ReadFile(in)
		if err != nil {
			return nil, err
		}
		links = append(links, texts...)
	}
	return links, nil
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
