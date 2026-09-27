package aggregator

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestAggregatorExtractThreatFox checks the request sent to ThreatFox and the payloads made from
// a response: one per ip:port indicator, with domain indicators skipped.
func TestAggregatorExtractThreatFox(test *testing.T) {
	test.Parallel()

	upstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "threatfox_taginfo.json")))
	aggregator, logs := newTestAggregator(test, upstream.server.Client())
	aggregator.abusechAPIKey = "secret"

	payloads, err := aggregator.extractThreatFox(test.Context(), Source{
		Name:  THREATFOX_SOURCE_NAME,
		URL:   upstream.server.URL + "/api/v1/",
		Query: validThreatFoxQuery,
	})
	if nil != err {
		test.Fatalf("extractThreatFox() error = %v, want nil", err)
	}

	// The request is a POST of the query as JSON, authenticated by the Auth-Key header.
	requests := upstream.received()
	if 1 != len(requests) {
		test.Fatalf("extractThreatFox() sent %d requests, want 1", len(requests))
	}

	wantHeaders := map[string]string{"Auth-Key": "secret", "Accept": "application/json", "Content-Type": "application/json"}
	for name, value := range wantHeaders {
		if value != requests[0].header.Get(name) {
			test.Errorf("extractThreatFox() header %s = %q, want %q", name, requests[0].header.Get(name), value)
		}
	}

	var sentQuery APIQuery
	if err := json.Unmarshal(requests[0].body, &sentQuery); nil != err {
		test.Fatalf("decoding request body %q: %v", requests[0].body, err)
	}

	if http.MethodPost != requests[0].method || "/api/v1/" != requests[0].path || validThreatFoxQuery != sentQuery {
		test.Errorf("extractThreatFox() request = %+v with query %+v, want POST /api/v1/ with %+v", requests[0], sentQuery, validThreatFoxQuery)
	}

	// Three of the four indicators are ip:port. The metadata matches what is already published.
	want := []Payload{
		newTestPayload("155.94.154.152", THREATFOX_SOURCE_NAME, fixedTime, `{"firstSeen":"2026-09-14T11:12:50","port":"80",`+
			`"reference":"https://www.shodan.io/host/155.94.154.152#80","malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/unknown",`+
			`"id":"1917395","ioc":"155.94.154.152:80","threat_type":"botnet_cc"}`, "unknown malware"),
		newTestPayload("155.94.154.152", THREATFOX_SOURCE_NAME, fixedTime, `{"firstSeen":"2026-09-14T11:11:45","port":"50050",`+
			`"reference":"https://www.shodan.io/host/155.94.154.152#50050","malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike",`+
			`"id":"1917357","ioc":"155.94.154.152:50050","threat_type":"botnet_cc"}`, "cobalt strike"),
		newTestPayload("94.230.141.123", THREATFOX_SOURCE_NAME, fixedTime, `{"firstSeen":"2026-06-23T06:51:37","port":"443",`+
			`"reference":null,"malware_malpedia":"https://malpedia.caad.fkie.fraunhofer.de/details/win.sliver",`+
			`"id":"1836199","ioc":"94.230.141.123:443","threat_type":"botnet_cc"}`, "sliver"),
	}
	if diff := cmp.Diff(want, payloads, payloadComparison); "" != diff {
		test.Fatalf("extractThreatFox() mismatch (-want +got):\n%s", diff)
	}

	// The published files have always had these keys in this order.
	if string(want[2].Results[0].Metadata) != string(payloads[2].Results[0].Metadata) {
		test.Errorf("extractThreatFox() metadata = %s, want %s", payloads[2].Results[0].Metadata, want[2].Results[0].Metadata)
	}

	if strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), `msg="skipping unsupported entry"`) {
		test.Errorf("extractThreatFox() logs = %q, want only the skipped domain indicator at debug level", logs)
	}
}

// TestAggregatorExtractThreatFoxNoData checks that a successful response without indicators
// yields no payloads and no error.
func TestAggregatorExtractThreatFoxNoData(test *testing.T) {
	test.Parallel()

	for _, response := range []string{
		`{"query_status": "ok", "data": []}`,
		`{"query_status": "ok", "data": null}`,
		`{"query_status": "ok"}`,
	} {
		upstream := newFakeUpstream(test, http.StatusOK, response)
		aggregator, _ := newTestAggregator(test, upstream.server.Client())

		payloads, err := aggregator.extractThreatFox(test.Context(), Source{URL: upstream.server.URL, Query: validThreatFoxQuery})
		if nil != err || 0 != len(payloads) {
			test.Errorf("extractThreatFox() of %s = (%v, %v), want no payloads and no error", response, payloads, err)
		}
	}
}

// TestAggregatorExtractThreatFoxErrors checks that a query that can't be sent, and a response
// that isn't a successful ThreatFox answer, fail the whole source.
func TestAggregatorExtractThreatFoxErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name     string
		status   int
		response string
		// source overrides the source queried, when set.
		source *Source
	}{
		{name: "error status", status: http.StatusUnauthorized, response: `{}`},
		{name: "invalid json", status: http.StatusOK, response: `{`},
		{name: "query failed", status: http.StatusOK, response: `{"query_status": "illegal_tag", "data": "Tag not found"}`},
		{name: "no result", status: http.StatusOK, response: `{"query_status": "no_result"}`},
		{name: "data not a list", status: http.StatusOK, response: `{"query_status": "ok", "data": "Your search did not yield any results"}`},
		// JSON text must be valid UTF-8, so this query can't be encoded.
		{name: "query not encodable", source: &Source{URL: "https://127.0.0.1/", Query: APIQuery{Query: "\xff", Limit: 1}}},
		{name: "invalid url", source: &Source{URL: "https://[::1", Query: validThreatFoxQuery}},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			upstream := newFakeUpstream(subtest, testCase.status, testCase.response)
			aggregator, _ := newTestAggregator(subtest, upstream.server.Client())

			source := Source{URL: upstream.server.URL, Query: validThreatFoxQuery}
			if nil != testCase.source {
				source = *testCase.source
			}

			if _, err := aggregator.extractThreatFox(subtest.Context(), source); nil == err {
				subtest.Error("extractThreatFox() error = nil, want error")
			}
		})
	}
}

// TestNewThreatFoxPayload checks how single indicators are converted: the defaults ThreatFox
// data needs, and the indicators that are refused.
func TestNewThreatFoxPayload(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name      string
		indicator string
		// wantFlag is the payload's flag, or "" when the indicator must be refused.
		wantFlag string
		// wantUnsupported is true when the refusal must be errUnsupportedEntry.
		wantUnsupported bool
	}{
		{name: "missing malware family", indicator: `{"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "first_seen": "2026-05-19 00:00:00 UTC"}`, wantFlag: "unknown"},
		{name: "domain", indicator: `{"ioc": "evil.example", "ioc_type": "domain"}`, wantUnsupported: true},
		{name: "not an object", indicator: `1`},
		{name: "no port", indicator: `{"ioc": "1.2.3.4", "ioc_type": "ip:port"}`},
		// IPv6 ip:port indicators have more than one colon, so they aren't parsed.
		{name: "ipv6", indicator: `{"ioc": "::1:80", "ioc_type": "ip:port", "first_seen": "2026-05-19 00:00:00 UTC"}`},
		{name: "port out of range", indicator: `{"ioc": "1.2.3.4:70000", "ioc_type": "ip:port", "first_seen": "2026-05-19 00:00:00 UTC"}`},
		{name: "malformed first_seen", indicator: `{"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "first_seen": "yesterday"}`},
		{name: "missing first_seen", indicator: `{"ioc": "1.2.3.4:80", "ioc_type": "ip:port"}`},
		{name: "non-string ioc", indicator: `{"ioc": 1, "ioc_type": "ip:port"}`},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			payload, err := newThreatFoxPayload(jsontext.Value(testCase.indicator), isoTime(fixedTime))

			if "" == testCase.wantFlag {
				if nil == err || testCase.wantUnsupported != errors.Is(err, errUnsupportedEntry) {
					subtest.Errorf("newThreatFoxPayload(%s) error = %v, want an error (unsupported: %v)", testCase.indicator, err, testCase.wantUnsupported)
				}

				return
			}

			if nil != err || testCase.wantFlag != payload.Flags[0] {
				subtest.Errorf("newThreatFoxPayload(%s) = (%+v, %v), want flag %q", testCase.indicator, payload, err, testCase.wantFlag)
			}
		})
	}
}

// FuzzNewThreatFoxPayload checks that newThreatFoxPayload never panics, and only returns
// storable payloads from ThreatFox, whatever the indicator contains.
func FuzzNewThreatFoxPayload(fuzzer *testing.F) {
	var response threatFoxResponse
	if err := json.Unmarshal(readTestdata(fuzzer, "threatfox_taginfo.json"), &response); nil != err {
		fuzzer.Fatalf("decoding fixture: %v", err)
	}

	for _, indicator := range response.Data {
		fuzzer.Add([]byte(indicator))
	}

	fuzzer.Add([]byte(`{"ioc": "[::1]:80", "ioc_type": "ip:port", "first_seen": "2026-05-19 00:00:00 CET"}`))

	fuzzer.Fuzz(func(test *testing.T, rawIndicator []byte) {
		payload, err := newThreatFoxPayload(jsontext.Value(rawIndicator), isoTime(time.Time{}))
		if nil != err {
			return // Refusing a malformed indicator is allowed; panicking isn't.
		}

		checkExtractedPayload(test, payload, THREATFOX_SOURCE_NAME)
	})
}

// FuzzAggregatorConvertThreatFoxResponse checks that convertThreatFoxResponse never panics,
// and only returns storable payloads from ThreatFox, whatever the response contains.
func FuzzAggregatorConvertThreatFoxResponse(fuzzer *testing.F) {
	fuzzer.Add(readTestdata(fuzzer, "threatfox_taginfo.json"))
	fuzzer.Add([]byte(`{"query_status": "ok", "data": [1, "x", null]}`))
	fuzzer.Add([]byte(`{"query_status": "ok", "query_status": "ok"}`))

	aggregator, _ := newTestAggregator(fuzzer, &http.Client{})
	aggregator.logger = slog.New(slog.DiscardHandler)

	fuzzer.Fuzz(func(test *testing.T, responseBody []byte) {
		payloads, err := aggregator.convertThreatFoxResponse(test.Context(), responseBody)
		if nil != err {
			return // Rejecting a malformed response is allowed; panicking isn't.
		}

		for _, payload := range payloads {
			checkExtractedPayload(test, payload, THREATFOX_SOURCE_NAME)
		}
	})
}
