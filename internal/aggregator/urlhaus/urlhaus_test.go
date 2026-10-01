package urlhaus

import (
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

// newTestEnricher returns an enricher that queries server with the Auth-Key "secret".
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server) *Enricher {
	testingContext.Helper()

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/v1/host/"}

	enricher, err := New(config, server.Upstream(testingContext), "secret")
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks that the URL must be https and the key set.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://urlhaus-api.abuse.ch/"}, nil, "secret"); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}

	if _, err := New(aggregator.SourceConfig{URL: "https://urlhaus-api.abuse.ch/"}, nil, ""); nil == err || !strings.Contains(err.Error(), "Auth-Key") {
		test.Errorf("New(no key) error = %v, want an Auth-Key error", err)
	}
}

// TestEnricherLookup checks that the host is sent as a form with the Auth-Key, and the report
// made from a recorded response.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "110.136.50.184.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("110.136.50.184"))
	if nil != err {
		test.Fatalf("Lookup() error = %v, want nil", err)
	}

	request := server.Requests()[0]
	form, _ := url.ParseQuery(string(request.Body)) // An invalid form fails the comparison below.

	isExpectedRequest := http.MethodPost == request.Method && "/v1/host/" == request.Path &&
		"110.136.50.184" == form.Get("host") && "secret" == request.Header.Get("Auth-Key")
	if !isExpectedRequest {
		test.Errorf("Lookup() sent %+v, want a form POST of the host with the Auth-Key", request)
	}

	want := []aggregator.Report{aggregator.NewReport("", nil, Data{
		URLhausReference: "https://urlhaus.abuse.ch/host/110.136.50.184/",
		FirstSeen:        time.Date(2026, 10, 1, 10, 32, 9, 0, time.UTC),
		URLCount:         1,
		Blacklists:       Blacklists{SpamhausDBL: "not listed", SURBL: "not listed"},
		URLs: []URL{{
			ID:        "3926131",
			URL:       "http://110.136.50.184:38922/i",
			Status:    "online",
			DateAdded: time.Date(2026, 10, 1, 10, 32, 13, 0, time.UTC),
			Threat:    "malware_download",
		}},
	})}
	if diff := cmp.Diff(want, reports); "" != diff {
		test.Errorf("Lookup() mismatch (-want +got):\n%s", diff)
	}
}

// TestEnricherLookupNoResults checks that a host URLhaus doesn't know gives no reports.
func TestEnricherLookupNoResults(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "no_results.json")})

	if reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil != err || 0 != len(reports) {
		test.Errorf("Lookup() = (%v, %v), want no reports and no error", reports, err)
	}
}

// TestEnricherLookupErrors checks that a failed request, a failed query or a malformed
// response fails the lookup.
func TestEnricherLookupErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name     string
		response fakeupstream.Response
		// wantErr is part of the error Lookup must return.
		wantErr string
	}{
		{name: "error status", response: fakeupstream.Response{Status: http.StatusUnauthorized}, wantErr: "401"},
		{name: "invalid json", response: fakeupstream.Response{Status: http.StatusOK, Body: `{`}, wantErr: "decoding"},
		{name: "query failed", response: fakeupstream.Response{Status: http.StatusOK, Body: `{"query_status": "invalid_host"}`}, wantErr: "invalid_host"},
		{name: "bad first seen", response: fakeupstream.Response{Status: http.StatusOK, Body: `{"query_status": "ok", "firstseen": "today"}`}, wantErr: "firstseen"},
		{
			name:     "bad url count",
			response: fakeupstream.Response{Status: http.StatusOK, Body: `{"query_status": "ok", "firstseen": "2026-10-01 10:32:09 UTC", "url_count": "many"}`},
			wantErr:  "url_count",
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			server := fakeupstream.New(subtest, testCase.response)

			_, err := newTestEnricher(subtest, server).Lookup(subtest.Context(), netip.MustParseAddr("192.0.2.1"))
			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("Lookup() error = %v, want one containing %q", err, testCase.wantErr)
			}
		})
	}
}

// TestNewDataSortsURLs checks that URLs are sorted by numeric ID, and that a URL with an
// unparsable date keeps no date rather than failing.
func TestNewDataSortsURLs(test *testing.T) {
	test.Parallel()

	data, err := newData(response{
		FirstSeen: "2026-10-01 10:32:09 UTC",
		URLCount:  "3",
		URLs:      []hostedURL{{ID: "10"}, {ID: "9", DateAdded: "yesterday"}, {ID: "100"}},
	})
	if nil != err {
		test.Fatalf("newData() error = %v, want nil", err)
	}

	ids := []string{data.URLs[0].ID, data.URLs[1].ID, data.URLs[2].ID}
	if !cmp.Equal([]string{"9", "10", "100"}, ids) || !data.URLs[0].DateAdded.IsZero() {
		test.Errorf("newData() URLs = %+v, want them in numeric order with the bad date left out", data.URLs)
	}
}

// FuzzNewReports checks that newReports never panics, and that what it accepts is at most one
// report with valid data.
func FuzzNewReports(fuzzer *testing.F) {
	fuzzer.Add([]byte(readTestdata(fuzzer, "110.136.50.184.json")))
	fuzzer.Add([]byte(readTestdata(fuzzer, "no_results.json")))

	fuzzer.Fuzz(func(test *testing.T, body []byte) {
		reports, err := newReports(body)
		if nil != err {
			return // Refusing a malformed response is allowed; panicking isn't.
		}

		if len(reports) > 1 || (1 == len(reports) && !reports[0].Data.IsValid()) {
			test.Errorf("newReports(%q) = %+v, want at most one report with valid data", body, reports)
		}
	})
}
