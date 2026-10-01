package aggregator

import (
	"encoding/json/jsontext"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// fixedTime is the clock reading of every test aggregator. It's never changed.
var fixedTime = time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)

// recordComparison makes cmp compare records by meaning: addresses by value, times by instant,
// JSON data by its canonical form, so key order and spacing don't matter, and nil and empty
// collections alike, because both encode as []. It's never changed after the tests start.
var recordComparison = cmp.Options{
	cmpopts.EquateEmpty(),
	cmp.Comparer(func(first, second netip.Addr) bool { return first == second }),
	cmp.Comparer(func(first, second time.Time) bool { return first.Equal(second) }),
	// Two empty values are left to EquateEmpty, so only one option ever applies.
	cmp.FilterValues(
		func(first, second jsontext.Value) bool { return 0 != len(first) || 0 != len(second) },
		cmp.Transformer("canonicalJSON", func(value jsontext.Value) string {
			canonical := value.Clone()
			if err := canonical.Canonicalize(); nil != err {
				return string(value)
			}

			return string(canonical)
		}),
	),
}

// newTestStore returns a Store in a new temporary directory, closed when the test ends.
func newTestStore(testingContext testing.TB) *Store {
	testingContext.Helper()

	store, err := NewStore(testingContext.TempDir())
	if nil != err {
		testingContext.Fatalf("NewStore() error = %v, want nil", err)
	}

	// Cleanup runs the function literal when the test and its subtests have finished.
	testingContext.Cleanup(func() {
		if err := store.Close(); nil != err {
			testingContext.Errorf("Close() error = %v, want nil", err)
		}
	})

	return store
}

// readTestdata returns the content of a fixture in testdata.
func readTestdata(testingContext testing.TB, name string) []byte {
	testingContext.Helper()

	content, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: name is a fixture name written in the test.
	if nil != err {
		testingContext.Fatalf("reading fixture %q: %v", name, err)
	}

	return content
}

// writeStoreFile writes content to name inside store's directory, creating its directories.
func writeStoreFile(testingContext testing.TB, store *Store, name string, content []byte) {
	testingContext.Helper()

	if err := store.root.MkdirAll(filepath.Dir(name), OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
		testingContext.Fatalf("creating directory for %q: %v", name, err)
	}

	if err := store.root.WriteFile(name, content, OUTPUT_FILE_PERMISSIONS); nil != err {
		testingContext.Fatalf("writing %q: %v", name, err)
	}
}

// readStoredRecord decodes the file the store holds for address.
func readStoredRecord(testingContext testing.TB, store *Store, address string) Record {
	testingContext.Helper()

	content, err := store.root.ReadFile(addressFileName(netip.MustParseAddr(address)))
	if nil != err {
		testingContext.Fatalf("reading stored record for %q: %v", address, err)
	}

	record, err := decodeRecord(content)
	if nil != err {
		testingContext.Fatalf("decoding stored record for %q: %v", address, err)
	}

	return record
}

// newTestReport returns a report with the given key, flags and JSON data.
func newTestReport(key, data string, flags ...string) Report {
	return Report{Key: key, Flags: flags, Data: jsontext.Value(data)}
}
