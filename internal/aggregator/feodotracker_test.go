package aggregator

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestAggregatorExtractFeodoTracker checks a real Feodo Tracker blocklist: the published
// fields are passed through and the others are dropped.
func TestAggregatorExtractFeodoTracker(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})

	payloads, err := aggregator.extractFeodoTracker(test.Context(), bytes.NewReader(readTestdata(test, "feodotracker.json")))
	if nil != err {
		test.Fatalf("extractFeodoTracker() error = %v, want nil", err)
	}

	// The published files have always had these keys in this order.
	wantMetadata := `{"country":"US","firstSeen":"2025-12-30 13:56:31","lastOnline":"2026-03-12",` +
		`"hostname":"ec2-50-16-16-211.compute-1.amazonaws.com","port":443}`
	want := []Payload{newTestPayload("50.16.16.211", FEODOTRACKER_SOURCE_NAME, fixedTime, wantMetadata, "qakbot")}

	if diff := cmp.Diff(want, payloads, payloadComparison); "" != diff {
		test.Fatalf("extractFeodoTracker() mismatch (-want +got):\n%s", diff)
	}

	if wantMetadata != string(payloads[0].Results[0].Metadata) {
		test.Errorf("extractFeodoTracker() metadata = %s, want %s", payloads[0].Results[0].Metadata, wantMetadata)
	}

	if 0 != logs.Len() {
		test.Errorf("extractFeodoTracker() logged %q, want nothing for a valid blocklist", logs)
	}
}

// TestAggregatorExtractFeodoTrackerEntries checks that a null hostname stays null, and that
// malformed entries are skipped with a warning.
func TestAggregatorExtractFeodoTrackerEntries(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})
	body := `[
		{"ip_address": "1.2.3.4", "port": 443, "hostname": null, "country": "US", "first_seen": "a", "last_online": "b", "malware": "QakBot"},
		1,
		{"ip_address": "not-an-ip", "malware": "QakBot"},
		{"ip_address": "1.2.3.5", "port": "443", "malware": "QakBot"},
		{"ip_address": "1.2.3.6"}
	]`

	payloads, err := aggregator.extractFeodoTracker(test.Context(), strings.NewReader(body))
	if nil != err {
		test.Fatalf("extractFeodoTracker() error = %v, want nil", err)
	}

	wantMetadata := `{"country":"US","firstSeen":"a","lastOnline":"b","hostname":null,"port":443}`
	want := []Payload{newTestPayload("1.2.3.4", FEODOTRACKER_SOURCE_NAME, fixedTime, wantMetadata, "qakbot")}

	if diff := cmp.Diff(want, payloads, payloadComparison); "" != diff {
		test.Errorf("extractFeodoTracker() mismatch (-want +got):\n%s", diff)
	}

	if wantWarnings := 4; wantWarnings != strings.Count(logs.String(), "level=WARN") {
		test.Errorf("extractFeodoTracker() logs = %q, want %d warnings", logs, wantWarnings)
	}
}

// TestAggregatorExtractFeodoTrackerErrors checks that a body that isn't a JSON list fails the
// whole blocklist.
func TestAggregatorExtractFeodoTrackerErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: "["},
		{name: "not a list", body: `{"ip_address": "1.2.3.4"}`},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			aggregator, _ := newTestAggregator(subtest, &http.Client{})
			if _, err := aggregator.extractFeodoTracker(subtest.Context(), strings.NewReader(testCase.body)); nil == err {
				subtest.Errorf("extractFeodoTracker(%q) error = nil, want error", testCase.body)
			}
		})
	}
}

// FuzzAggregatorExtractFeodoTracker checks that extractFeodoTracker never panics, and only
// returns storable payloads from Feodo Tracker, whatever the blocklist contains.
func FuzzAggregatorExtractFeodoTracker(fuzzer *testing.F) {
	fuzzer.Add(readTestdata(fuzzer, "feodotracker.json"))
	fuzzer.Add([]byte(`[{"ip_address": "::1", "malware": "X", "hostname": "h", "port": -1}]`))
	fuzzer.Add([]byte(`[null, [], {}]`))

	aggregator, _ := newTestAggregator(fuzzer, &http.Client{})
	aggregator.logger = slog.New(slog.DiscardHandler)

	fuzzer.Fuzz(func(test *testing.T, body []byte) {
		payloads, err := aggregator.extractFeodoTracker(test.Context(), bytes.NewReader(body))
		if nil != err {
			return // Rejecting a malformed blocklist is allowed; panicking isn't.
		}

		for _, payload := range payloads {
			checkExtractedPayload(test, payload, FEODOTRACKER_SOURCE_NAME)
		}
	})
}
