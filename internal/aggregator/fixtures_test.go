package aggregator

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// fixedTime is the clock reading of every test aggregator. It's never changed.
var fixedTime = time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC)

// validThreatFoxQuery is the query from the repository's sources.json. It's never changed.
var validThreatFoxQuery = APIQuery{Query: "taginfo", Tag: "c2 ", Days: 1, Limit: 1000}

// payloadComparison makes cmp compare payloads by meaning: addresses by value, timestamps by
// instant, and metadata by its canonical JSON, so key order and spacing don't matter. It's
// never changed after the tests start.
var payloadComparison = cmp.Options{
	cmp.Comparer(func(first, second netip.Addr) bool { return first == second }),
	cmp.Comparer(func(first, second isoTime) bool { return time.Time(first).Equal(time.Time(second)) }),
	cmp.Transformer("canonicalJSON", func(value jsontext.Value) string {
		canonical := value.Clone()
		if err := canonical.Canonicalize(); nil != err {
			return string(value)
		}

		return string(canonical)
	}),
}

// newTestAggregator returns an Aggregator with no sources, a fixed clock and a store in a new
// temporary directory, sending requests with httpClient. Its logs, at every level, go to the
// returned buffer.
func newTestAggregator(testingContext testing.TB, httpClient *http.Client) (*Aggregator, *bytes.Buffer) {
	testingContext.Helper()

	var logs bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	aggregator, err := New(Sources{}, newTestStore(testingContext), httpClient, WithLogger(logger))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	aggregator.now = func() time.Time { return fixedTime }

	return aggregator, &logs
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

// readStoredPayload decodes the file the store holds for address.
func readStoredPayload(testingContext testing.TB, store *Store, address string) Payload {
	testingContext.Helper()

	content, err := store.root.ReadFile(addressFileName(netip.MustParseAddr(address)))
	if nil != err {
		testingContext.Fatalf("reading stored payload for %q: %v", address, err)
	}

	var payload Payload
	if err := json.Unmarshal(content, &payload); nil != err {
		testingContext.Fatalf("decoding stored payload for %q: %v", address, err)
	}

	return payload
}

// newTestPayload returns a payload for address with one result per flag from source, each
// with the given datetime and metadata.
func newTestPayload(address, source string, datetime time.Time, metadata string, flags ...string) Payload {
	payload := Payload{IP: netip.MustParseAddr(address), Flags: flags}
	for _, flag := range flags {
		payload.Results = append(payload.Results, Result{
			Source:   source,
			Datetime: isoTime(datetime),
			Flags:    []string{flag},
			Metadata: jsontext.Value(metadata),
		})
	}

	return payload
}

// checkExtractedPayload reports an error unless payload is what an extractor for source must
// produce: a storable address and exactly one result, from source, with one non-empty,
// lower-case flag and valid metadata.
func checkExtractedPayload(testingContext testing.TB, payload Payload, source string) {
	testingContext.Helper()

	if !isStorableAddress(payload.IP) {
		testingContext.Errorf("payload address %v isn't storable", payload.IP)
	}

	if 1 != len(payload.Results) || 1 != len(payload.Flags) {
		testingContext.Fatalf("payload = %+v, want one flag and one result", payload)
	}

	result := payload.Results[0]
	isValidFlag := "" != payload.Flags[0] && strings.ToLower(payload.Flags[0]) == payload.Flags[0]

	if source != result.Source || !isValidFlag || !result.Metadata.IsValid() {
		testingContext.Errorf("payload = %+v, want source %q, one lower-case flag and valid metadata", payload, source)
	}
}
