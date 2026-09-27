package aggregator

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestIsoTimeMarshalText checks that timestamps are written like Python's isoformat(), which
// the published data has always used.
func TestIsoTimeMarshalText(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name   string
		moment time.Time
		want   string
	}{
		{name: "whole seconds", moment: time.Date(2026, 5, 19, 1, 2, 3, 0, time.UTC), want: "2026-05-19T01:02:03"},
		{name: "microseconds", moment: time.Date(2026, 5, 19, 1, 2, 3, 123456000, time.UTC), want: "2026-05-19T01:02:03.123456"},
		// Python's datetime has no nanoseconds, so anything below a microsecond is dropped.
		{name: "sub-microsecond truncated", moment: time.Date(2026, 5, 19, 1, 2, 3, 999, time.UTC), want: "2026-05-19T01:02:03"},
		{name: "leading zero microseconds", moment: time.Date(2026, 5, 19, 1, 2, 3, 1000, time.UTC), want: "2026-05-19T01:02:03.000001"},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			timestamp := isoTime(testCase.moment)

			got, err := timestamp.MarshalText()
			if nil != err {
				subtest.Fatalf("MarshalText() error = %v, want nil", err)
			}

			if testCase.want != string(got) {
				subtest.Errorf("MarshalText() = %q, want %q", got, testCase.want)
			}
		})
	}
}

// TestIsoTimeUnmarshalText checks that both timestamp forms are read as UTC, and that anything
// else is rejected.
func TestIsoTimeUnmarshalText(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		text    string
		want    time.Time
		wantErr bool
	}{
		{name: "whole seconds", text: "2026-05-19T01:02:03", want: time.Date(2026, 5, 19, 1, 2, 3, 0, time.UTC)},
		{name: "microseconds", text: "2026-05-22T22:59:13.819427", want: time.Date(2026, 5, 22, 22, 59, 13, 819427000, time.UTC)},
		{name: "time zone", text: "2026-05-19T01:02:03Z", wantErr: true},
		{name: "date only", text: "2026-05-19", wantErr: true},
		{name: "empty", text: "", wantErr: true},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			var timestamp isoTime

			err := timestamp.UnmarshalText([]byte(testCase.text))
			if testCase.wantErr != (nil != err) {
				subtest.Fatalf("UnmarshalText(%q) error = %v, want error %v", testCase.text, err, testCase.wantErr)
			}

			if !testCase.want.Equal(time.Time(timestamp)) || testCase.want.Location() != time.Time(timestamp).Location() {
				subtest.Errorf("UnmarshalText(%q) = %v, want %v", testCase.text, time.Time(timestamp), testCase.want)
			}
		})
	}
}

// FuzzIsoTimeUnmarshalText checks that any timestamp UnmarshalText accepts is written back
// the way MarshalText writes it, so reading and rewriting a file never changes a timestamp
// that was written by this program.
func FuzzIsoTimeUnmarshalText(fuzzer *testing.F) {
	fuzzer.Add("2026-05-19T01:02:03")
	fuzzer.Add("2026-05-22T22:59:13.819427")
	fuzzer.Add("2026-05-19T01:02:03.1")
	fuzzer.Add("")

	fuzzer.Fuzz(func(test *testing.T, text string) {
		var timestamp isoTime
		if err := timestamp.UnmarshalText([]byte(text)); nil != err {
			return // Rejecting bad input is allowed; panicking isn't.
		}

		written, err := timestamp.MarshalText()
		if nil != err {
			test.Fatalf("MarshalText() after UnmarshalText(%q) error = %v", text, err)
		}

		var reread isoTime
		if err := reread.UnmarshalText(written); nil != err {
			test.Fatalf("UnmarshalText(%q) of MarshalText() output error = %v", written, err)
		}

		rewritten, rewriteErr := reread.MarshalText()
		if nil != rewriteErr || !bytes.Equal(written, rewritten) {
			test.Errorf("rewriting %q = (%q, %v), want it unchanged", written, rewritten, rewriteErr)
		}
	})
}

// TestIsoTimeIsZero checks that only an unset timestamp is zero.
func TestIsoTimeIsZero(test *testing.T) {
	test.Parallel()

	var unset isoTime
	if !unset.IsZero() {
		test.Error("isoTime{}.IsZero() = false, want true")
	}

	set := isoTime(fixedTime)
	if set.IsZero() {
		test.Errorf("isoTime(%v).IsZero() = true, want false", fixedTime)
	}
}

// TestParseAddress checks that feed addresses are parsed, and that anything that can't name
// a file is refused.
func TestParseAddress(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{name: "ipv4", input: "192.168.1.1"},
		{name: "ipv6", input: "2001:db8::1"},
		{name: "ipv4 mapped ipv6", input: "::ffff:1.2.3.4"},
		{name: "empty", input: "", wantErr: true},
		{name: "octet out of range", input: "256.1.1.1", wantErr: true},
		// A leading zero could mean octal, so it's ambiguous and refused.
		{name: "leading zero", input: "192.168.01.1", wantErr: true},
		{name: "address and port", input: "1.2.3.4:80", wantErr: true},
		{name: "path traversal", input: "../../etc/passwd", wantErr: true},
		{name: "ipv6 zone", input: "fe80::1%eth0", wantErr: true},
		{name: "ipv6 zone with a path", input: "fe80::1%../../x", wantErr: true},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			address, err := parseAddress(testCase.input)
			if testCase.wantErr != (nil != err) {
				subtest.Fatalf("parseAddress(%q) error = %v, want error %v", testCase.input, err, testCase.wantErr)
			}

			if !testCase.wantErr && testCase.input != address.String() {
				subtest.Errorf("parseAddress(%q) = %v, want %v", testCase.input, address, testCase.input)
			}
		})
	}
}

// TestNewPayload checks the payload built for one sighting: one lower-cased flag, and the
// metadata encoded as JSON with its fields in declaration order.
func TestNewPayload(test *testing.T) {
	test.Parallel()

	metadata := struct {
		Second string `json:"second"`
		First  int    `json:"first"`
	}{Second: "b", First: 1}

	got, err := newPayload(netip.MustParseAddr("1.2.3.4"), "test", "Cobalt Strike", isoTime(fixedTime), metadata)
	if nil != err {
		test.Fatalf("newPayload() error = %v, want nil", err)
	}

	want := newTestPayload("1.2.3.4", "test", fixedTime, `{"second":"b","first":1}`, "cobalt strike")
	if diff := cmp.Diff(want, got, payloadComparison); "" != diff {
		test.Errorf("newPayload() mismatch (-want +got):\n%s", diff)
	}

	if `{"second":"b","first":1}` != string(got.Results[0].Metadata) {
		test.Errorf("newPayload().Results[0].Metadata = %s, want fields in declaration order", got.Results[0].Metadata)
	}
}

// TestNewPayloadErrors checks that a sighting without a malware family, or with metadata that
// can't be published as JSON, is refused.
func TestNewPayloadErrors(test *testing.T) {
	test.Parallel()

	address := netip.MustParseAddr("1.2.3.4")

	if _, err := newPayload(address, "test", "", isoTime(fixedTime), struct{}{}); nil == err {
		test.Error(`newPayload() with family "" error = nil, want error`)
	}

	// JSON text must be valid UTF-8, so invalid bytes from a feed can't be published.
	invalidMetadata := map[string]string{"value": "\xff"}
	if _, err := newPayload(address, "test", "family", isoTime(fixedTime), invalidMetadata); nil == err {
		test.Error("newPayload() with invalid UTF-8 metadata error = nil, want error")
	}
}

// TestConvertEntries checks that converted entries are kept in order, malformed entries are
// skipped with a warning and unsupported entries are skipped quietly.
func TestConvertEntries(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})
	entries := []string{"1.1.1.1", "malformed", "unsupported", "2.2.2.2"}

	got := convertEntries(test.Context(), aggregator.logger, "test", entries, func(entry string) (Payload, error) {
		switch entry {
		case "malformed":
			return Payload{}, errors.New("malformed entry")
		case "unsupported":
			return Payload{}, errUnsupportedEntry
		}

		return Payload{IP: netip.MustParseAddr(entry)}, nil
	})

	want := []Payload{{IP: netip.MustParseAddr("1.1.1.1")}, {IP: netip.MustParseAddr("2.2.2.2")}}
	if diff := cmp.Diff(want, got, payloadComparison); "" != diff {
		test.Errorf("convertEntries() mismatch (-want +got):\n%s", diff)
	}

	for _, wantLog := range []string{
		`level=WARN msg="skipping malformed entry" source=test entry_index=1 error="malformed entry"`,
		`level=DEBUG msg="skipping unsupported entry" source=test entry_index=2`,
	} {
		if !strings.Contains(logs.String(), wantLog) {
			test.Errorf("convertEntries() logs = %q, want them to contain %q", logs, wantLog)
		}
	}
}

// TestPayloadRoundTripsPublishedFile checks that a file written by the Go aggregator is read
// and written back byte for byte, so rewriting a file changes only what really changed.
func TestPayloadRoundTripsPublishedFile(test *testing.T) {
	test.Parallel()

	published := readTestdata(test, "published_threatfox.json")

	var payload Payload
	if err := json.Unmarshal(published, &payload); nil != err {
		test.Fatalf("decoding published file: %v", err)
	}

	store := newTestStore(test)
	if err := writePayload(store.root, "payload.json", payload); nil != err {
		test.Fatalf("writePayload() error = %v, want nil", err)
	}

	written, err := store.root.ReadFile("payload.json")
	if nil != err {
		test.Fatalf("reading written file: %v", err)
	}

	if diff := cmp.Diff(string(published), string(written)); "" != diff {
		test.Errorf("rewritten file mismatch (-want +got):\n%s", diff)
	}
}

// TestPayloadReadsPythonFile checks that files written by the earlier Python aggregator, with
// metadata keys in insertion order and no final newline, are still read, and that their
// metadata keeps its key order when written back.
func TestPayloadReadsPythonFile(test *testing.T) {
	test.Parallel()

	var payload Payload
	if err := json.Unmarshal(readTestdata(test, "published_criminalip.json"), &payload); nil != err {
		test.Fatalf("decoding published file: %v", err)
	}

	want := newTestPayload(
		"99.209.179.82",
		CRIMINALIP_SOURCE_NAME,
		time.Date(2026, 5, 22, 22, 59, 13, 819427000, time.UTC),
		`{"port": "80", "score": "Critical/Critical", "country": "ca", "scanTime": "2026-05-20 20:42:46"}`,
		"c2_meshagent",
	)
	if diff := cmp.Diff(want, payload, payloadComparison); "" != diff {
		test.Errorf("decoded Python file mismatch (-want +got):\n%s", diff)
	}

	encoded, err := json.Marshal(payload)
	if nil != err {
		test.Fatalf("encoding decoded Python file: %v", err)
	}

	wantMetadata := `"metadata":{"port":"80","score":"Critical/Critical","country":"ca","scanTime":"2026-05-20 20:42:46"}`
	if !strings.Contains(string(encoded), wantMetadata) {
		test.Errorf("re-encoded Python file = %s, want metadata keys in their original order", encoded)
	}
}
