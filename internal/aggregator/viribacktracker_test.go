package aggregator

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/google/go-cmp/cmp"
)

// TestAggregatorExtractViriBackTracker checks a real ViriBack feed: one payload per row, with
// the first-seen date written as an ISO timestamp.
func TestAggregatorExtractViriBackTracker(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})

	payloads, err := aggregator.extractViriBackTracker(test.Context(), bytes.NewReader(readTestdata(test, "viribacktracker.csv")))
	if nil != err {
		test.Fatalf("extractViriBackTracker() error = %v, want nil", err)
	}

	if 5 != len(payloads) {
		test.Fatalf("extractViriBackTracker() returned %d payloads, want 5", len(payloads))
	}

	// The published files have always had these keys in this order.
	want := newTestPayload(
		"47.105.68.108",
		VIRIBACKTRACKER_SOURCE_NAME,
		fixedTime,
		`{"firstSeen":"2026-09-26T00:00:00","login":"http://47.105.68.108:8082/login/index"}`,
		"vshell",
	)
	if diff := cmp.Diff(want, payloads[0], payloadComparison); "" != diff {
		test.Errorf("extractViriBackTracker() first payload mismatch (-want +got):\n%s", diff)
	}

	if string(want.Results[0].Metadata) != string(payloads[0].Results[0].Metadata) {
		test.Errorf("extractViriBackTracker() metadata = %s, want %s", payloads[0].Results[0].Metadata, want.Results[0].Metadata)
	}

	if 0 != logs.Len() {
		test.Errorf("extractViriBackTracker() logged %q, want nothing for a valid feed", logs)
	}
}

// TestAggregatorExtractViriBackTrackerDates checks that unpadded days and months are read, and
// that rows with a malformed date or address are skipped with a warning.
func TestAggregatorExtractViriBackTrackerDates(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})
	body := "Family,URL,IP,FirstSeen\n" +
		"AgentTesla,http://5.6.7.8/,5.6.7.8,1-2-2026\n" +
		"AgentTesla,http://5.6.7.9/,5.6.7.9,2026-02-01\n" +
		"AgentTesla,http://x/,not-an-ip,1-2-2026\n"

	payloads, err := aggregator.extractViriBackTracker(test.Context(), strings.NewReader(body))
	if nil != err {
		test.Fatalf("extractViriBackTracker() error = %v, want nil", err)
	}

	want := []Payload{newTestPayload(
		"5.6.7.8",
		VIRIBACKTRACKER_SOURCE_NAME,
		fixedTime,
		`{"firstSeen":"2026-02-01T00:00:00","login":"http://5.6.7.8/"}`,
		"agenttesla",
	)}
	if diff := cmp.Diff(want, payloads, payloadComparison); "" != diff {
		test.Errorf("extractViriBackTracker() mismatch (-want +got):\n%s", diff)
	}

	if wantWarnings := 2; wantWarnings != strings.Count(logs.String(), "level=WARN") {
		test.Errorf("extractViriBackTracker() logs = %q, want %d warnings", logs, wantWarnings)
	}
}

// TestAggregatorExtractViriBackTrackerReadError checks that a body that can't be read fails
// the feed.
func TestAggregatorExtractViriBackTrackerReadError(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})
	readErr := errors.New("connection reset")

	if _, err := aggregator.extractViriBackTracker(test.Context(), iotest.ErrReader(readErr)); !errors.Is(err, readErr) {
		test.Errorf("extractViriBackTracker() of a failing body error = %v, want %v", err, readErr)
	}
}

// FuzzAggregatorExtractViriBackTracker checks that extractViriBackTracker never fails or
// panics, and only returns storable payloads from ViriBack, whatever the feed contains.
func FuzzAggregatorExtractViriBackTracker(fuzzer *testing.F) {
	fuzzer.Add(readTestdata(fuzzer, "viribacktracker.csv"))
	fuzzer.Add([]byte("h\nfam,login,1.2.3.4,31-2-2026\n"))
	fuzzer.Add([]byte("h\nfam,login,::1,1-1-0001\n"))

	aggregator, _ := newTestAggregator(fuzzer, &http.Client{})
	aggregator.logger = slog.New(slog.DiscardHandler)

	fuzzer.Fuzz(func(test *testing.T, body []byte) {
		payloads, err := aggregator.extractViriBackTracker(test.Context(), bytes.NewReader(body))
		if nil != err {
			test.Fatalf("extractViriBackTracker(%q) error = %v, want nil", body, err)
		}

		for _, payload := range payloads {
			checkExtractedPayload(test, payload, VIRIBACKTRACKER_SOURCE_NAME)
		}
	})
}
