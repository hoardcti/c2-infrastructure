package internetdb

import (
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
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

// newTestEnricher returns an enricher that queries server.
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server) *Enricher {
	testingContext.Helper()

	enricher, err := New(aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/"}, server.Upstream(testingContext))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidURL checks that InternetDB must be queried over https.
func TestNewRejectsInvalidURL(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://internetdb.shodan.io/"}, nil); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}
}

// TestEnricherLookup checks the request for an address and the report made from a recorded
// response, with every list sorted.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "1.15.76.39.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("1.15.76.39"))
	if nil != err {
		test.Fatalf("Lookup() error = %v, want nil", err)
	}

	if requests := server.Requests(); 1 != len(requests) || "/1.15.76.39" != requests[0].Path || http.MethodGet != requests[0].Method {
		test.Errorf("Lookup() sent %+v, want GET /1.15.76.39", requests)
	}

	want := []aggregator.Report{aggregator.NewReport("", nil, Data{
		Ports: []int{22, 123, 6789, 8000, 8080, 8081, 8443, 50050},
		CPEs: []string{
			"cpe:/a:apache:tomcat", "cpe:/a:helpsystems:cobalt_strike", "cpe:/a:ntp:ntp:3",
			"cpe:/a:openbsd:openssh:8.9p1", "cpe:/o:canonical:ubuntu_linux",
		},
		Tags: []string{"c2", "self-signed"},
	})}
	if diff := cmp.Diff(want, reports); "" != diff {
		test.Errorf("Lookup() mismatch (-want +got):\n%s", diff)
	}
}

// TestEnricherLookupNotFound checks that an address InternetDB knows nothing about gives no
// reports and no error.
func TestEnricherLookupNotFound(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusNotFound, Body: readTestdata(test, "not_found.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1"))
	if nil != err || 0 != len(reports) {
		test.Errorf("Lookup() = (%v, %v), want no reports and no error", reports, err)
	}
}

// TestEnricherLookupErrors checks that a failed request or an invalid response fails the
// lookup.
func TestEnricherLookupErrors(test *testing.T) {
	test.Parallel()

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusInternalServerError},
		{Status: http.StatusOK, Body: `{"ports": "22"}`},
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
	fuzzer.Add([]byte(`{"ports": [2, 1, 2], "tags": null}`))

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
