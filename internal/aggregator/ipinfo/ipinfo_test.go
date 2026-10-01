package ipinfo

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// newTestEnricher returns an enricher that queries server with the token "secret".
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server) *Enricher {
	testingContext.Helper()

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/lite/"}

	enricher, err := New(config, server.Upstream(testingContext), "secret")
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks that the URL must be https and the token set.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://api.ipinfo.io/lite/"}, nil, "secret"); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}

	if _, err := New(aggregator.SourceConfig{URL: "https://api.ipinfo.io/lite/"}, nil, ""); nil == err || !strings.Contains(err.Error(), "token") {
		test.Errorf("New(no token) error = %v, want a token error", err)
	}
}

// TestEnricherLookup checks that the token is sent as a bearer token, never in the URL, and
// the report made from a recorded response.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "1.15.76.39.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("1.15.76.39"))
	if nil != err {
		test.Fatalf("Lookup() error = %v, want nil", err)
	}

	requests := server.Requests()
	isExpectedRequest := 1 == len(requests) && "/lite/1.15.76.39" == requests[0].Path && "" == requests[0].Query &&
		"Bearer secret" == requests[0].Header.Get("Authorization")
	if !isExpectedRequest {
		test.Errorf("Lookup() sent %+v, want GET /lite/1.15.76.39 with a bearer token", requests)
	}

	want := []aggregator.Report{aggregator.NewReport("", nil, Data{
		ASN:           "AS45090",
		ASName:        "Shenzhen Tencent Computer Systems Company Limited",
		ASDomain:      "tencent.com",
		CountryCode:   "CN",
		Country:       "China",
		ContinentCode: "AS",
		Continent:     "Asia",
	})}
	if diff := cmp.Diff(want, reports); "" != diff {
		test.Errorf("Lookup() mismatch (-want +got):\n%s", diff)
	}
}

// TestEnricherLookupErrors checks that a rejected token or an invalid response fails the
// lookup.
func TestEnricherLookupErrors(test *testing.T) {
	test.Parallel()

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusForbidden, Body: `{"status": 403, "error": {"title": "Unknown token"}}`},
		{Status: http.StatusOK, Body: `[]`},
	} {
		server := fakeupstream.New(test, response)

		if _, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil == err {
			test.Errorf("Lookup() of %+v error = nil, want error", response)
		}
	}
}

// FuzzNewReports checks that newReports never panics, and that what it accepts is one report
// with valid data.
func FuzzNewReports(fuzzer *testing.F) {
	fuzzer.Add([]byte(readTestdata(fuzzer, "1.15.76.39.json")))
	fuzzer.Add([]byte(`{"ip": "192.0.2.1", "bogon": true}`))

	fuzzer.Fuzz(func(test *testing.T, body []byte) {
		reports, err := newReports(body)
		if nil != err {
			return // Refusing a malformed response is allowed; panicking isn't.
		}

		if 1 != len(reports) || !reports[0].Data.IsValid() {
			test.Errorf("newReports(%q) = %+v, want one report with valid data", body, reports)
		}
	})
}
