package abuseipdb

import (
	"encoding/json/jsontext"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/fakeupstream"
)

// readTestdata returns the content of a fixture in testdata.
func readTestdata(testingContext testing.TB, name string) string {
	testingContext.Helper()

	content, err := os.ReadFile(filepath.Join("testdata", name)) //nolint:gosec // G304: name is a fixture name written in the test.
	if nil != err {
		testingContext.Fatalf("reading fixture %q: %v", name, err)
	}

	return string(content)
}

// newTestEnricher returns an enricher that queries server with the key "secret" and the given
// options.
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server, options string) *Enricher {
	testingContext.Helper()

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/api/v2/check", Options: jsontext.Value(options)}

	enricher, err := New(config, server.Upstream(testingContext), "secret")
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks every setting New refuses.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		config  aggregator.SourceConfig
		apiKey  aggregator.APIKey
		wantErr string
	}{
		{name: "url not https", config: aggregator.SourceConfig{URL: "http://api.abuseipdb.com/"}, apiKey: "key", wantErr: "checking url"},
		{name: "unknown option", config: aggregator.SourceConfig{URL: "https://api.abuseipdb.com/", Options: jsontext.Value(`{"days": 1}`)}, apiKey: "key", wantErr: "checking options"},
		{name: "period too long", config: aggregator.SourceConfig{URL: "https://api.abuseipdb.com/", Options: jsontext.Value(`{"max_age_in_days": 366}`)}, apiKey: "key", wantErr: "max_age_in_days"},
		{name: "period too short", config: aggregator.SourceConfig{URL: "https://api.abuseipdb.com/", Options: jsontext.Value(`{"max_age_in_days": 0}`)}, apiKey: "key", wantErr: "max_age_in_days"},
		{name: "no key", config: aggregator.SourceConfig{URL: "https://api.abuseipdb.com/"}, wantErr: "key is required"},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if _, err := New(testCase.config, nil, testCase.apiKey); nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("New() error = %v, want one containing %q", err, testCase.wantErr)
			}
		})
	}
}

// TestEnricherLookup checks the query and key sent, that the default period is used, and the
// report made from a recorded response.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "1.15.76.39.json")})

	reports, err := newTestEnricher(test, server, "").Lookup(test.Context(), netip.MustParseAddr("1.15.76.39"))
	if nil != err {
		test.Fatalf("Lookup() error = %v, want nil", err)
	}

	request := server.Requests()[0]
	query, _ := url.ParseQuery(request.Query) // An invalid query fails the comparison below.

	isExpectedRequest := "/api/v2/check" == request.Path && "1.15.76.39" == query.Get("ipAddress") &&
		"90" == query.Get("maxAgeInDays") && "secret" == request.Header.Get("Key") && !strings.Contains(request.Query, "secret")
	if !isExpectedRequest {
		test.Errorf("Lookup() sent %+v, want the address and period in the query and the key in a header", request)
	}

	want := []aggregator.Report{aggregator.NewReport("", nil, Data{
		LastReportedAt: new(time.Date(2026, 4, 7, 19, 29, 1, 0, time.UTC)),
		MaxAgeInDays:   DEFAULT_MAX_AGE_IN_DAYS,
		IsWhitelisted:  new(false),
		UsageType:      "Data Center/Web Hosting/Transit", //nolint:misspell // AbuseIPDB's own spelling.
		ISP:            "Tencent cloud computing (Beijing) Co., Ltd.",
		Domain:         "tencentcloud.com",
		CountryCode:    "CN",
	})}
	if diff := cmp.Diff(want, reports); "" != diff {
		test.Errorf("Lookup() mismatch (-want +got):\n%s", diff)
	}
}

// TestEnricherLookupConfiguredPeriod checks that a configured period is sent and stored, and
// that a never-reported address stores a null last report.
func TestEnricherLookupConfiguredPeriod(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: `{"data": {"abuseConfidenceScore": 0, "lastReportedAt": null}}`})

	reports, err := newTestEnricher(test, server, `{"max_age_in_days": 30}`).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1"))
	if nil != err || 1 != len(reports) {
		test.Fatalf("Lookup() = (%v, %v), want one report", reports, err)
	}

	isExpected := strings.Contains(server.Requests()[0].Query, "maxAgeInDays=30") &&
		strings.Contains(string(reports[0].Data), `"max_age_in_days":30`) && strings.Contains(string(reports[0].Data), `"last_reported_at":null`)
	if !isExpected {
		test.Errorf("Lookup() sent %q and stored %s, want a 30-day period and a null last report", server.Requests()[0].Query, reports[0].Data)
	}
}

// TestEnricherLookupErrors checks that a used-up quota or an invalid response fails the
// lookup.
func TestEnricherLookupErrors(test *testing.T) {
	test.Parallel()

	quota := http.Header{}
	quota.Set("Retry-After", "36000")

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusTooManyRequests, Header: quota, Body: `{"errors": [{"detail": "Daily rate limit of 1000 requests exceeded"}]}`},
		{Status: http.StatusOK, Body: `{"data": []}`},
	} {
		server := fakeupstream.New(test, response)

		if _, err := newTestEnricher(test, server, "").Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil == err {
			test.Errorf("Lookup() of %+v error = nil, want error", response)
		}
	}
}

// FuzzNewReports checks that newReports never panics, and that what it accepts is one report
// with valid data.
func FuzzNewReports(fuzzer *testing.F) {
	fuzzer.Add([]byte(readTestdata(fuzzer, "1.15.76.39.json")))
	fuzzer.Add([]byte(`{"data": {"lastReportedAt": "2026-04-07T19:29:01+02:00", "hostnames": ["b", "a"]}}`))

	fuzzer.Fuzz(func(test *testing.T, body []byte) {
		reports, err := newReports(body, DEFAULT_MAX_AGE_IN_DAYS)
		if nil != err {
			return // Refusing a malformed response is allowed; panicking isn't.
		}

		if 1 != len(reports) || !reports[0].Data.IsValid() {
			test.Errorf("newReports(%q) = %+v, want one report with valid data", body, reports)
		}
	})
}
