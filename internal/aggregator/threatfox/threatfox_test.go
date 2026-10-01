package threatfox

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/fakeupstream"
)

// addressComparison makes cmp compare addresses by value. It's never changed.
var addressComparison = cmp.Comparer(func(first, second netip.Addr) bool { return first == second })

// validOptions are the options in the repository's sources.json.
const validOptions = `{"query": "taginfo", "tag": "c2 ", "days": 1, "limit": 1000}`

// newTestFeed returns a feed that queries server, logging at every level to the returned
// buffer.
func newTestFeed(testingContext testing.TB, server *fakeupstream.Server) (*Feed, *bytes.Buffer) {
	testingContext.Helper()

	var logs bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	config := aggregator.SourceConfig{
		Name:    SOURCE_NAME,
		URL:     server.URL() + "/api/v1/",
		Options: jsontext.Value(validOptions),
	}

	feed, err := New(config, server.Upstream(testingContext), "secret", logger)
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return feed, &logs
}

// readTestdata returns the content of a fixture in testdata.
func readTestdata(testingContext testing.TB, name string) string {
	testingContext.Helper()

	content, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: name is a fixture name written in the test.
	if nil != err {
		testingContext.Fatalf("reading fixture %q: %v", name, err)
	}

	return string(content)
}

// TestNewRejectsInvalidConfiguration checks every setting New refuses.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		url     string
		options string
		apiKey  aggregator.APIKey
		// wantErr is part of the error New must return.
		wantErr string
	}{
		{name: "url not https", url: "http://example.com/", options: validOptions, apiKey: "key", wantErr: "checking url"},
		{name: "unknown option", url: "https://example.com/", options: `{"query": "taginfo", "limit": 1, "tags": "c2"}`, apiKey: "key", wantErr: "checking options"},
		{name: "no query", url: "https://example.com/", options: `{"limit": 1}`, apiKey: "key", wantErr: "a query and a limit"},
		{name: "no limit", url: "https://example.com/", options: `{"query": "taginfo"}`, apiKey: "key", wantErr: "a query and a limit"},
		{name: "no key", url: "https://example.com/", options: validOptions, wantErr: "Auth-Key is required"},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			config := aggregator.SourceConfig{URL: testCase.url, Options: jsontext.Value(testCase.options)}

			_, err := New(config, nil, testCase.apiKey, slog.New(slog.DiscardHandler))
			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("New() error = %v, want one containing %q", err, testCase.wantErr)
			}
		})
	}
}

// TestFeedCollect checks the request sent to ThreatFox and the sightings made from a
// response: one per ip:port indicator, keyed by its ThreatFox ID, with the domain indicator
// skipped.
func TestFeedCollect(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "taginfo.json")})
	feed, logs := newTestFeed(test, server)

	sightings, err := feed.Collect(test.Context())
	if nil != err {
		test.Fatalf("Collect() error = %v, want nil", err)
	}

	// The request is a POST of the query as JSON, authenticated by the Auth-Key header.
	requests := server.Requests()
	if 1 != len(requests) {
		test.Fatalf("Collect() sent %d requests, want 1", len(requests))
	}

	var sentQuery Query
	if err := json.Unmarshal(requests[0].Body, &sentQuery); nil != err {
		test.Fatalf("decoding request body %q: %v", requests[0].Body, err)
	}

	isExpectedRequest := http.MethodPost == requests[0].Method && "/api/v1/" == requests[0].Path &&
		"secret" == requests[0].Header.Get("Auth-Key") && "application/json" == requests[0].Header.Get("Content-Type") &&
		(Query{Query: "taginfo", Tag: "c2 ", Days: 1, Limit: 1000}) == sentQuery
	if !isExpectedRequest {
		test.Errorf("Collect() sent %+v with query %+v, want a POST of the query with the Auth-Key", requests[0], sentQuery)
	}

	// Three of the four indicators are ip:port.
	want := []aggregator.Sighting{
		newWantSighting("155.94.154.152", "1917395", "unknown malware", Data{
			IOC: "155.94.154.152:80", Port: 80, ThreatType: "botnet_cc", Malware: "Unknown malware",
			MalwareMalpedia: "https://malpedia.caad.fkie.fraunhofer.de/details/unknown", ConfidenceLevel: 75,
			FirstSeen: time.Date(2026, 9, 14, 11, 12, 50, 0, time.UTC),
			Reference: new("https://www.shodan.io/host/155.94.154.152#80"), Tags: []string{"c2"},
		}),
		newWantSighting("155.94.154.152", "1917357", "cobalt strike", Data{
			IOC: "155.94.154.152:50050", Port: 50050, ThreatType: "botnet_cc", Malware: "Cobalt Strike",
			MalwareMalpedia: "https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike", ConfidenceLevel: 100,
			FirstSeen: time.Date(2026, 9, 14, 11, 11, 45, 0, time.UTC),
			Reference: new("https://www.shodan.io/host/155.94.154.152#50050"), Tags: []string{"CobaltStrike", "c2"},
		}),
		newWantSighting("94.230.141.123", "1836199", "sliver", Data{
			IOC: "94.230.141.123:443", Port: 443, ThreatType: "botnet_cc", Malware: "Sliver",
			MalwareMalpedia: "https://malpedia.caad.fkie.fraunhofer.de/details/win.sliver", ConfidenceLevel: 100,
			FirstSeen: time.Date(2026, 6, 23, 6, 51, 37, 0, time.UTC), Tags: []string{"c2", "sliver"},
		}),
	}
	if diff := cmp.Diff(want, sightings, addressComparison); "" != diff {
		test.Errorf("Collect() mismatch (-want +got):\n%s", diff)
	}

	if strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), `msg="skipping unsupported entry"`) {
		test.Errorf("Collect() logs = %q, want only the skipped domain indicator at debug level", logs.String())
	}
}

// newWantSighting returns the sighting a test expects for address.
func newWantSighting(address, key, flag string, data Data) aggregator.Sighting {
	return aggregator.Sighting{
		Address: netip.MustParseAddr(address),
		Report:  aggregator.NewReport(key, []string{flag}, data),
	}
}

// TestFeedCollectWithoutIndicators checks that a successful query without indicators gives no
// sightings and no error.
func TestFeedCollectWithoutIndicators(test *testing.T) {
	test.Parallel()

	for _, body := range []string{
		`{"query_status": "ok", "data": []}`,
		`{"query_status": "ok", "data": null}`,
		`{"query_status": "ok"}`,
		`{"query_status": "no_result", "data": "Your search did not yield any results"}`,
	} {
		server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: body})
		feed, _ := newTestFeed(test, server)

		if sightings, err := feed.Collect(test.Context()); nil != err || 0 != len(sightings) {
			test.Errorf("Collect() of %s = (%v, %v), want no sightings and no error", body, sightings, err)
		}
	}
}

// TestFeedCollectErrors checks that a response that isn't a successful ThreatFox answer fails
// the whole feed.
func TestFeedCollectErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name   string
		status int
		body   string
		// wantErr is part of the error Collect must return.
		wantErr string
	}{
		{name: "error status", status: http.StatusUnauthorized, body: `{}`, wantErr: "unexpected HTTP status 401"},
		{name: "invalid json", status: http.StatusOK, body: `{`, wantErr: "decoding ThreatFox response"},
		{name: "query failed", status: http.StatusOK, body: `{"query_status": "unknown_auth_key"}`, wantErr: `status "unknown_auth_key"`},
		{name: "data not a list", status: http.StatusOK, body: `{"query_status": "ok", "data": "text"}`, wantErr: "decoding ThreatFox indicators"},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			server := fakeupstream.New(subtest, fakeupstream.Response{Status: testCase.status, Body: testCase.body})
			feed, _ := newTestFeed(subtest, server)

			if _, err := feed.Collect(subtest.Context()); nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("Collect() error = %v, want one containing %q", err, testCase.wantErr)
			}
		})
	}
}

// TestNewSighting checks how single indicators are converted: the defaults ThreatFox data
// needs, and the indicators that are refused.
func TestNewSighting(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name      string
		indicator string
		// wantFlag is the sighting's flag, or "" when the indicator must be refused.
		wantFlag string
		// wantUnsupported is true when the refusal must be aggregator.ErrUnsupportedEntry.
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
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			sighting, err := newSighting(jsontext.Value(testCase.indicator))

			if "" == testCase.wantFlag {
				if nil == err || testCase.wantUnsupported != errors.Is(err, aggregator.ErrUnsupportedEntry) {
					subtest.Errorf("newSighting(%s) error = %v, want an error (unsupported: %v)", testCase.indicator, err, testCase.wantUnsupported)
				}

				return
			}

			if nil != err || !cmp.Equal([]string{testCase.wantFlag}, sighting.Report.Flags) {
				subtest.Errorf("newSighting(%s) = (%+v, %v), want flag %q", testCase.indicator, sighting, err, testCase.wantFlag)
			}
		})
	}
}

// FuzzNewSighting checks that newSighting never panics, and only returns storable addresses
// with one flag, whatever the indicator contains.
func FuzzNewSighting(fuzzer *testing.F) {
	var decoded response
	if err := json.Unmarshal([]byte(readTestdata(fuzzer, "taginfo.json")), &decoded); nil != err {
		fuzzer.Fatalf("decoding fixture: %v", err)
	}

	var indicators []jsontext.Value
	if err := json.Unmarshal(decoded.Data, &indicators); nil != err {
		fuzzer.Fatalf("decoding fixture indicators: %v", err)
	}

	for _, indicator := range indicators {
		fuzzer.Add([]byte(indicator))
	}

	fuzzer.Add([]byte(`{"ioc": "[::1]:80", "ioc_type": "ip:port", "first_seen": "2026-05-19 00:00:00 CET"}`))

	fuzzer.Fuzz(func(test *testing.T, rawIndicator []byte) {
		sighting, err := newSighting(jsontext.Value(rawIndicator))
		if nil != err {
			return // Refusing a malformed indicator is allowed; panicking isn't.
		}

		if !sighting.Address.IsValid() || 1 != len(sighting.Report.Flags) || !sighting.Report.Data.IsValid() {
			test.Errorf("newSighting(%q) = %+v, want a valid address, one flag and valid data", rawIndicator, sighting)
		}
	})
}
