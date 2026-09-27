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

// TestAggregatorExtractCriminalIP checks a real Criminal IP feed: one payload per row, with the
// row's values passed through as metadata.
func TestAggregatorExtractCriminalIP(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})

	payloads, err := aggregator.extractCriminalIP(test.Context(), bytes.NewReader(readTestdata(test, "criminalip.csv")))
	if nil != err {
		test.Fatalf("extractCriminalIP() error = %v, want nil", err)
	}

	if 5 != len(payloads) {
		test.Fatalf("extractCriminalIP() returned %d payloads, want 5", len(payloads))
	}

	want := newTestPayload(
		"35.172.12.146",
		CRIMINALIP_SOURCE_NAME,
		fixedTime,
		`{"port":"443","score":"Critical/Critical","country":"us","scanTime":"2026-09-24 18:21:09"}`,
		"c2_meshagent",
	)
	if diff := cmp.Diff(want, payloads[0], payloadComparison); "" != diff {
		test.Errorf("extractCriminalIP() first payload mismatch (-want +got):\n%s", diff)
	}

	// The published files have always had these keys in this order.
	wantMetadata := `{"port":"443","score":"Critical/Critical","country":"us","scanTime":"2026-09-24 18:21:09"}`
	if wantMetadata != string(payloads[0].Results[0].Metadata) {
		test.Errorf("extractCriminalIP() metadata = %s, want %s", payloads[0].Results[0].Metadata, wantMetadata)
	}

	if 0 != logs.Len() {
		test.Errorf("extractCriminalIP() logged %q, want nothing for a valid feed", logs)
	}
}

// TestAggregatorExtractCriminalIPSkipsMalformedRows checks that malformed rows are skipped with
// a warning and the rest of the feed is kept.
func TestAggregatorExtractCriminalIPSkipsMalformedRows(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})
	body := "IP,flag,port,score,country,scanTime\n" +
		"1.2.3.4,Cobalt Strike,443,Critical,US,2026-05-19 01:00:00\n" +
		"not-an-ip,Metasploit,80,Dangerous,DE,2026-05-19 02:00:00\n" +
		"5.6.7.8,,80,Dangerous,DE,2026-05-19 02:00:00\n" +
		"9.9.9.9,short row\n" +
		"5.6.7.8,Metasploit,80,Dangerous,DE,2026-05-19 02:00:00\n"

	payloads, err := aggregator.extractCriminalIP(test.Context(), strings.NewReader(body))
	if nil != err {
		test.Fatalf("extractCriminalIP() error = %v, want nil", err)
	}

	var gotAddresses []string
	for _, payload := range payloads {
		gotAddresses = append(gotAddresses, payload.IP.String()+" "+payload.Flags[0])
	}

	if diff := cmp.Diff([]string{"1.2.3.4 cobalt strike", "5.6.7.8 metasploit"}, gotAddresses); "" != diff {
		test.Errorf("extractCriminalIP() payloads mismatch (-want +got):\n%s", diff)
	}

	if want := 3; want != strings.Count(logs.String(), "level=WARN") {
		test.Errorf("extractCriminalIP() logs = %q, want %d warnings", logs, want)
	}
}

// TestAggregatorExtractCriminalIPReadError checks that a body that can't be read fails the feed.
func TestAggregatorExtractCriminalIPReadError(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})
	readErr := errors.New("connection reset")

	if _, err := aggregator.extractCriminalIP(test.Context(), iotest.ErrReader(readErr)); !errors.Is(err, readErr) {
		test.Errorf("extractCriminalIP() of a failing body error = %v, want %v", err, readErr)
	}
}

// FuzzAggregatorExtractCriminalIP checks that extractCriminalIP never fails or panics, and only
// returns storable payloads from Criminal IP, whatever the feed contains.
func FuzzAggregatorExtractCriminalIP(fuzzer *testing.F) {
	fuzzer.Add(readTestdata(fuzzer, "criminalip.csv"))
	fuzzer.Add([]byte("IP,flag,port,score,country,scanTime\n\"1.2.3.4\",\"a\"b,1,2,3,4\n"))
	fuzzer.Add([]byte("header\nfe80::1%eth0,x,1,2,3,4\n"))
	fuzzer.Add([]byte(""))

	aggregator, _ := newTestAggregator(fuzzer, &http.Client{})
	aggregator.logger = slog.New(slog.DiscardHandler)

	fuzzer.Fuzz(func(test *testing.T, body []byte) {
		payloads, err := aggregator.extractCriminalIP(test.Context(), bytes.NewReader(body))
		if nil != err {
			test.Fatalf("extractCriminalIP(%q) error = %v, want nil", body, err)
		}

		for _, payload := range payloads {
			checkExtractedPayload(test, payload, CRIMINALIP_SOURCE_NAME)
		}
	})
}
