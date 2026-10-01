package aggregator

import (
	"encoding/json/jsontext"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestNewReport checks that flags are normalised and data is encoded deterministically, with
// invalid UTF-8 from upstream replaced rather than refused.
func TestNewReport(test *testing.T) {
	test.Parallel()

	data := struct {
		// Counts is a map, whose keys must come out sorted.
		Counts map[string]int `json:"counts"`
		// Text holds invalid UTF-8.
		Text string `json:"text"`
	}{Counts: map[string]int{"b": 2, "a": 1}, Text: "bad\xff"}

	report := NewReport("key", []string{"Cobalt Strike", "", "cobalt strike", "AsyncRAT"}, data)

	want := Report{
		Key:   "key",
		Flags: []string{"asyncrat", "cobalt strike"},
		Data:  jsontext.Value(`{"counts":{"a":1,"b":2},"text":"bad` + "�" + `"}`),
	}
	if diff := cmp.Diff(want, report); "" != diff {
		test.Errorf("NewReport() mismatch (-want +got):\n%s", diff)
	}
}

// TestNewReportPanicsOnUnencodableData checks that data encoding/json can't encode is treated
// as the programming mistake it is.
func TestNewReportPanicsOnUnencodableData(test *testing.T) {
	test.Parallel()

	// recover returns the value passed to panic when called in a deferred function, or nil if
	// nothing panicked.
	defer func() {
		if recovered := recover(); nil == recovered || !strings.Contains(recovered.(string), "chan int") { //nolint:forcetypeassert // NewReport panics with a string.
			test.Errorf("NewReport(channel) panic = %v, want a message naming the type", recovered)
		}
	}()

	NewReport("", nil, make(chan int))
}

// TestSortedUnique checks sorting and deduplication, that empty input gives nil, and that the
// caller's slice isn't changed.
func TestSortedUnique(test *testing.T) {
	test.Parallel()

	values := []string{"b", "a", "b"}
	if diff := cmp.Diff([]string{"a", "b"}, SortedUnique(values)); "" != diff {
		test.Errorf("SortedUnique(%q) mismatch (-want +got):\n%s", values, diff)
	}

	if !slices.Equal([]string{"b", "a", "b"}, values) {
		test.Errorf("SortedUnique() changed its input to %q", values)
	}

	if diff := cmp.Diff([]int{1, 2}, SortedUnique([]int{2, 1, 2})); "" != diff {
		test.Errorf("SortedUnique(ints) mismatch (-want +got):\n%s", diff)
	}

	if nil != SortedUnique([]int{}) || nil != SortedUnique[string](nil) {
		test.Error("SortedUnique(empty) != nil, want nil")
	}
}

// TestRecordAddReports checks how reports become history: identical reports extend the latest
// observation, anything else is appended, and nothing is ever replaced.
func TestRecordAddReports(test *testing.T) {
	test.Parallel()

	address := netip.MustParseAddr("192.0.2.1")
	first := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	second := first.Add(time.Hour)
	third := second.Add(time.Hour)

	// step is one call to addReports.
	type step struct {
		source  string
		reports []Report
		at      time.Time
	}

	testCases := []struct {
		name  string
		steps []step
		want  Record
	}{
		{
			name:  "first report creates an observation",
			steps: []step{{source: "feed", reports: []Report{newTestReport("1", `{"port":443}`, "sliver")}, at: first}},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, FirstSeen: first, LastSeen: first, Flags: []string{"sliver"},
				Sources: map[string]SourceHistory{"feed": {LastChecked: first, Observations: []Observation{
					{Key: "1", FirstObserved: first, LastObserved: first, Flags: []string{"sliver"}, Data: jsontext.Value(`{"port":443}`)},
				}}},
			},
		},
		{
			name: "identical report only extends the observation",
			steps: []step{
				{source: "feed", reports: []Report{newTestReport("1", `{"port":443,"service":"nginx"}`, "sliver")}, at: first},
				// The same data with its keys in another order is still the same report.
				{source: "feed", reports: []Report{newTestReport("1", `{"service":"nginx","port":443}`, "sliver")}, at: second},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, FirstSeen: first, LastSeen: second, Flags: []string{"sliver"},
				Sources: map[string]SourceHistory{"feed": {LastChecked: second, Observations: []Observation{
					{Key: "1", FirstObserved: first, LastObserved: second, Flags: []string{"sliver"}, Data: jsontext.Value(`{"port":443,"service":"nginx"}`)},
				}}},
			},
		},
		{
			name: "changed data keeps the old value",
			steps: []step{
				{source: "shodan", reports: []Report{newTestReport("", `{"port":443,"service":"nginx"}`)}, at: first},
				{source: "shodan", reports: []Report{newTestReport("", `{"port":443,"service":"Apache"}`)}, at: second},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, Flags: []string{},
				Sources: map[string]SourceHistory{"shodan": {LastChecked: second, Observations: []Observation{
					{FirstObserved: first, LastObserved: first, Data: jsontext.Value(`{"port":443,"service":"nginx"}`)},
					{FirstObserved: second, LastObserved: second, Data: jsontext.Value(`{"port":443,"service":"Apache"}`)},
				}}},
			},
		},
		{
			name: "changing back is recorded as another change",
			steps: []step{
				{source: "shodan", reports: []Report{newTestReport("", `{"service":"nginx"}`)}, at: first},
				{source: "shodan", reports: []Report{newTestReport("", `{"service":"Apache"}`)}, at: second},
				{source: "shodan", reports: []Report{newTestReport("", `{"service":"nginx"}`)}, at: third},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, Flags: []string{},
				Sources: map[string]SourceHistory{"shodan": {LastChecked: third, Observations: []Observation{
					{FirstObserved: first, LastObserved: first, Data: jsontext.Value(`{"service":"nginx"}`)},
					{FirstObserved: second, LastObserved: second, Data: jsontext.Value(`{"service":"Apache"}`)},
					{FirstObserved: third, LastObserved: third, Data: jsontext.Value(`{"service":"nginx"}`)},
				}}},
			},
		},
		{
			name: "changed flags are a change",
			steps: []step{
				{source: "feed", reports: []Report{newTestReport("1", `{}`, "unknown")}, at: first},
				{source: "feed", reports: []Report{newTestReport("1", `{}`, "sliver")}, at: second},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, FirstSeen: first, LastSeen: second, Flags: []string{"sliver", "unknown"},
				Sources: map[string]SourceHistory{"feed": {LastChecked: second, Observations: []Observation{
					{Key: "1", FirstObserved: first, LastObserved: first, Flags: []string{"unknown"}, Data: jsontext.Value(`{}`)},
					{Key: "1", FirstObserved: second, LastObserved: second, Flags: []string{"sliver"}, Data: jsontext.Value(`{}`)},
				}}},
			},
		},
		{
			name: "keys are followed separately, and duplicates in one run collapse",
			steps: []step{
				{source: "feed", reports: []Report{
					newTestReport("443", `{"port":443}`, "sliver"),
					newTestReport("80", `{"port":80}`, "sliver"),
					newTestReport("443", `{"port":443}`, "sliver"),
				}, at: first},
				{source: "feed", reports: []Report{newTestReport("443", `{"port":443}`, "sliver")}, at: second},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, FirstSeen: first, LastSeen: second, Flags: []string{"sliver"},
				Sources: map[string]SourceHistory{"feed": {LastChecked: second, Observations: []Observation{
					{Key: "443", FirstObserved: first, LastObserved: second, Flags: []string{"sliver"}, Data: jsontext.Value(`{"port":443}`)},
					{Key: "80", FirstObserved: first, LastObserved: first, Flags: []string{"sliver"}, Data: jsontext.Value(`{"port":80}`)},
				}}},
			},
		},
		{
			name: "several sources keep their own histories",
			steps: []step{
				{source: "threatfox", reports: []Report{newTestReport("1", `{"port":443}`, "sliver")}, at: first},
				{source: "feodotracker", reports: []Report{newTestReport("443", `{"port":443}`, "qakbot")}, at: second},
				{source: "ipinfo", reports: []Report{newTestReport("", `{"asn":"AS1"}`)}, at: third},
			},
			want: Record{
				// Only flagged observations count towards first_seen and last_seen.
				SchemaVersion: SCHEMA_VERSION, IP: address, FirstSeen: first, LastSeen: second, Flags: []string{"qakbot", "sliver"},
				Sources: map[string]SourceHistory{
					"threatfox": {LastChecked: first, Observations: []Observation{
						{Key: "1", FirstObserved: first, LastObserved: first, Flags: []string{"sliver"}, Data: jsontext.Value(`{"port":443}`)},
					}},
					"feodotracker": {LastChecked: second, Observations: []Observation{
						{Key: "443", FirstObserved: second, LastObserved: second, Flags: []string{"qakbot"}, Data: jsontext.Value(`{"port":443}`)},
					}},
					"ipinfo": {LastChecked: third, Observations: []Observation{
						{FirstObserved: third, LastObserved: third, Data: jsontext.Value(`{"asn":"AS1"}`)},
					}},
				},
			},
		},
		{
			name: "nothing reported still records the check",
			steps: []step{
				{source: "urlhaus", at: first},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, Flags: []string{},
				Sources: map[string]SourceHistory{"urlhaus": {LastChecked: first}},
			},
		},
		{
			name: "an older report never moves last_observed back",
			steps: []step{
				{source: "feed", reports: []Report{newTestReport("1", `{}`, "sliver")}, at: second},
				{source: "feed", reports: []Report{newTestReport("1", `{}`, "sliver")}, at: first},
			},
			want: Record{
				SchemaVersion: SCHEMA_VERSION, IP: address, FirstSeen: second, LastSeen: second, Flags: []string{"sliver"},
				Sources: map[string]SourceHistory{"feed": {LastChecked: first, Observations: []Observation{
					{Key: "1", FirstObserved: second, LastObserved: second, Flags: []string{"sliver"}, Data: jsontext.Value(`{}`)},
				}}},
			},
		},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			record := newRecord(address)
			for _, step := range testCase.steps {
				record.addReports(step.source, step.reports, step.at)
			}

			if diff := cmp.Diff(testCase.want, record, recordComparison); "" != diff {
				subtest.Errorf("addReports() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestRecordAddReportsClearsError checks that a successful lookup clears the source's last
// error, and that a record built without a sources map can still be added to.
func TestRecordAddReportsClearsError(test *testing.T) {
	test.Parallel()

	record := Record{IP: netip.MustParseAddr("192.0.2.1")}
	record.recordFailure("shodan", "timeout", fixedTime)

	if "timeout" != record.Sources["shodan"].LastError.Message {
		test.Fatalf("recordFailure() sources = %+v, want the error recorded", record.Sources)
	}

	record = Record{IP: netip.MustParseAddr("192.0.2.1")}
	record.addReports("shodan", nil, fixedTime)
	record.recordFailure("shodan", "timeout", fixedTime)
	record.addReports("shodan", nil, fixedTime.Add(time.Hour))

	if !record.Sources["shodan"].LastError.OccurredAt.IsZero() {
		test.Errorf("addReports() after a failure left last_error = %+v, want it cleared", record.Sources["shodan"].LastError)
	}
}

// TestRecordRecordFailure checks that a failure is recorded without touching the source's
// observations or last check.
func TestRecordRecordFailure(test *testing.T) {
	test.Parallel()

	record := newRecord(netip.MustParseAddr("192.0.2.1"))
	record.addReports("shodan", []Report{newTestReport("", `{"port":22}`)}, fixedTime)
	before := record.Sources["shodan"]

	failedAt := fixedTime.Add(time.Hour)
	record.recordFailure("shodan", "unexpected HTTP status 500", failedAt)

	want := before
	want.LastError = SourceError{OccurredAt: failedAt, Message: "unexpected HTTP status 500"}

	if diff := cmp.Diff(want, record.Sources["shodan"], recordComparison); "" != diff {
		test.Errorf("recordFailure() mismatch (-want +got):\n%s", diff)
	}
}

// TestRecordLastAttempt checks that the last attempt is the later of the last check and the
// last error.
func TestRecordLastAttempt(test *testing.T) {
	test.Parallel()

	record := newRecord(netip.MustParseAddr("192.0.2.1"))
	if _, ok := record.lastAttempt("shodan"); ok {
		test.Error("lastAttempt() of a source that never tried = ok, want not ok")
	}

	record.addReports("shodan", nil, fixedTime)
	if attempt, ok := record.lastAttempt("shodan"); !ok || !fixedTime.Equal(attempt) {
		test.Errorf("lastAttempt() after a check = (%v, %v), want %v", attempt, ok, fixedTime)
	}

	failedAt := fixedTime.Add(time.Hour)
	record.recordFailure("shodan", "timeout", failedAt)

	if attempt, ok := record.lastAttempt("shodan"); !ok || !failedAt.Equal(attempt) {
		test.Errorf("lastAttempt() after a failure = (%v, %v), want %v", attempt, ok, failedAt)
	}
}

// TestHasSameContentInvalidData checks that data that isn't valid JSON never counts as the
// same, so it's never silently merged.
func TestHasSameContentInvalidData(test *testing.T) {
	test.Parallel()

	observation := Observation{Data: jsontext.Value(`{`)}
	if hasSameContent(observation, newTestReport("", `{`)) {
		test.Error("hasSameContent(invalid, invalid) = true, want false")
	}
}

// TestDecodeRecordCurrentFormat checks that the current format round-trips, and that a record
// without sources gets an empty sources map.
func TestDecodeRecordCurrentFormat(test *testing.T) {
	test.Parallel()

	record := newRecord(netip.MustParseAddr("2001:db8::1"))
	record.addReports("feed", []Report{newTestReport("1", `{"port":443}`, "sliver")}, fixedTime)
	record.recordFailure("shodan", "timeout", fixedTime)

	content, err := encodeRecord(record)
	if nil != err {
		test.Fatalf("encodeRecord() error = %v, want nil", err)
	}

	decoded, err := decodeRecord(content)
	if nil != err {
		test.Fatalf("decodeRecord() error = %v, want nil", err)
	}

	if diff := cmp.Diff(record, decoded, recordComparison); "" != diff {
		test.Errorf("decodeRecord(encodeRecord()) mismatch (-want +got):\n%s", diff)
	}

	withoutSources, err := decodeRecord([]byte(`{"schema_version": 2, "ip": "192.0.2.1"}`))
	if nil != err || nil == withoutSources.Sources {
		test.Errorf("decodeRecord() = (%+v, %v), want a record with an empty sources map", withoutSources, err)
	}
}

// TestDecodeRecordVersion1 checks that a version 1 file written by the Go aggregator becomes
// one observation per result, keeping each result's metadata exactly.
func TestDecodeRecordVersion1(test *testing.T) {
	test.Parallel()

	decoded, err := decodeRecord(readTestdata(test, "published_threatfox.json"))
	if nil != err {
		test.Fatalf("decodeRecord() error = %v, want nil", err)
	}

	firstCollected := time.Date(2026, 9, 14, 11, 57, 26, 200758000, time.UTC)
	secondCollected := time.Date(2026, 9, 14, 11, 57, 26, 201476000, time.UTC)
	want := Record{
		SchemaVersion: SCHEMA_VERSION,
		IP:            netip.MustParseAddr("155.94.154.152"),
		FirstSeen:     firstCollected,
		LastSeen:      secondCollected,
		Flags:         []string{"cobalt strike", "unknown malware"},
		Sources: map[string]SourceHistory{"threatfox": {LastChecked: secondCollected, Observations: []Observation{
			{
				FirstObserved: firstCollected, LastObserved: firstCollected, Flags: []string{"unknown malware"},
				Data: jsontext.Value(`{"firstSeen":"2026-09-14T11:12:50","id":"1917395","ioc":"155.94.154.152:80",` +
					`"malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/unknown","port":"80",` +
					`"reference":"https://www.shodan.io/host/155.94.154.152#80","threat_type":"botnet_cc"}`),
			},
			{
				FirstObserved: secondCollected, LastObserved: secondCollected, Flags: []string{"cobalt strike"},
				Data: jsontext.Value(`{"firstSeen":"2026-09-14T11:11:45","id":"1917357","ioc":"155.94.154.152:50050",` +
					`"malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike","port":"50050",` +
					`"reference":"https://www.shodan.io/host/155.94.154.152#50050","threat_type":"botnet_cc"}`),
			},
		}}},
	}
	if diff := cmp.Diff(want, decoded, recordComparison); "" != diff {
		test.Errorf("decodeRecord() mismatch (-want +got):\n%s", diff)
	}
}

// TestDecodeRecordVersion1FromPython checks a version 1 file written by the earlier Python
// aggregator, whose keys are in insertion order and which has no final newline.
func TestDecodeRecordVersion1FromPython(test *testing.T) {
	test.Parallel()

	decoded, err := decodeRecord(readTestdata(test, "published_criminalip.json"))
	if nil != err {
		test.Fatalf("decodeRecord() error = %v, want nil", err)
	}

	observations := decoded.Sources["criminalip"].Observations
	if 1 != len(observations) || !observations[0].Data.IsValid() || 0 == len(decoded.Flags) {
		test.Errorf("decodeRecord() = %+v, want one criminalip observation with its metadata", decoded)
	}
}

// TestDecodeRecordErrors checks the files decodeRecord refuses.
func TestDecodeRecordErrors(test *testing.T) {
	test.Parallel()

	for _, invalid := range []string{
		`{`,
		`{"schema_version": 3}`,
		`{"schema_version": 2, "sources": []}`,
		`{"ip": "192.0.2.1", "results": [{"source": "feed", "datetime": "yesterday"}]}`,
	} {
		if _, err := decodeRecord([]byte(invalid)); nil == err {
			test.Errorf("decodeRecord(%s) error = nil, want error", invalid)
		}
	}
}

// FuzzDecodeRecord checks that decodeRecord never panics, and that whatever it accepts can be
// written back.
func FuzzDecodeRecord(fuzzer *testing.F) {
	fuzzer.Add(readTestdata(fuzzer, "published_threatfox.json"))
	fuzzer.Add(readTestdata(fuzzer, "published_criminalip.json"))
	fuzzer.Add([]byte(`{"schema_version": 2, "ip": "192.0.2.1", "sources": {"feed": {"observations": [{"data": {}}]}}}`))

	fuzzer.Fuzz(func(test *testing.T, content []byte) {
		record, err := decodeRecord(content)
		if nil != err {
			return // Refusing a malformed file is allowed; panicking isn't.
		}

		if _, err := encodeRecord(record); nil != err {
			test.Errorf("encodeRecord(decodeRecord(%q)) error = %v, want nil", content, err)
		}
	})
}
