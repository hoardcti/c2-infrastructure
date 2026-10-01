package shodan

import (
	"encoding/json/v2"
	"errors"
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

// newTestEnricher returns an enricher that queries server with the key "secret-key". The key
// is registered with the Upstream, as the command does.
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server) *Enricher {
	testingContext.Helper()

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/shodan/host/"}

	enricher, err := New(config, server.Upstream(testingContext, aggregator.WithRedactedSecret("secret-key")), "secret-key")
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks that the URL must be https and the key set.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://api.shodan.io/"}, nil, "secret"); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}

	if _, err := New(aggregator.SourceConfig{URL: "https://api.shodan.io/"}, nil, ""); nil == err || !strings.Contains(err.Error(), "key") {
		test.Errorf("New(no key) error = %v, want a key error", err)
	}
}

// TestEnricherLookup checks the request and the report made from a recorded response: one
// service per banner, sorted by port, with TLS and HTTP details and no scan timestamps.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "1.15.76.39.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("1.15.76.39"))
	if nil != err || 1 != len(reports) {
		test.Fatalf("Lookup() = (%v, %v), want one report", reports, err)
	}

	request := server.Requests()[0]
	if "/shodan/host/1.15.76.39" != request.Path || "key=secret-key" != request.Query {
		test.Errorf("Lookup() sent %+v, want the address path with the key in the query", request)
	}

	var got Data
	if err := json.Unmarshal(reports[0].Data, &got); nil != err {
		test.Fatalf("decoding report data: %v", err)
	}

	wantServices := []Service{
		{Port: 22, Transport: "tcp", Product: "OpenSSH", Version: "8.9p1 Ubuntu 3ubuntu0.6"},
		{Port: 8080, Transport: "tcp", Product: "Apache Tomcat", HTTPTitle: "Apache Tomcat/8.5.83"},
		{
			Port: 50050, Transport: "tcp", Product: "Cobalt Strike C2", Tags: []string{"c2", "self-signed"},
			JARM:                    "2ad2ad16d2ad2ad00042d42d00042ddb04deffa1705e2edc44cae1ed24a4da",
			CertificateSHA256:       "56a06a233bd30f693de25ef12cc19e8b2c92d3eb97dd969a2578df084c376478",
			CertificateSubject:      "Major Cobalt Strike",
			CertificateOrganisation: "cobaltstrike",
			CertificateIssuer:       "Major Cobalt Strike",
		},
	}
	if diff := cmp.Diff(wantServices, got.Services); "" != diff {
		test.Errorf("Lookup() services mismatch (-want +got):\n%s", diff)
	}

	if "AS45090" != got.ASN || !cmp.Equal([]string{"c2", "self-signed"}, got.Tags) || strings.Contains(string(reports[0].Data), "timestamp") {
		test.Errorf("Lookup() data = %s, want the host's ASN and tags without timestamps", reports[0].Data)
	}
}

// TestEnricherLookupNotFoundAndErrors checks that an unknown address gives no reports, and that
// a failed request or invalid response fails the lookup without showing the key.
func TestEnricherLookupNotFoundAndErrors(test *testing.T) {
	test.Parallel()

	notFound := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusNotFound, Body: `{"error": "No information available for that IP."}`})
	if reports, err := newTestEnricher(test, notFound).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil != err || 0 != len(reports) {
		test.Errorf("Lookup() of an unknown address = (%v, %v), want no reports and no error", reports, err)
	}

	// Shodan's answer when a free key asks for some hosts, recorded on 2026-10-01, is about
	// that host, so it must be a rejection of this lookup rather than of the key.
	forbidden := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusForbidden, Body: `{"error": "Requires membership or higher to access"}`})

	_, err := newTestEnricher(test, forbidden).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1"))
	isHostRejection := errors.Is(err, aggregator.ErrRejected) && !errors.Is(err, aggregator.ErrForbidden) &&
		strings.Contains(err.Error(), "the key's plan doesn't include this host") && strings.Contains(err.Error(), "Requires membership")
	if !isHostRejection {
		test.Errorf("Lookup() of a host the free plan refuses error = %v, want %v and not %v", err, aggregator.ErrRejected, aggregator.ErrForbidden)
	}

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusUnauthorized, Body: `{"error": "Invalid API key secret-key"}`},
		{Status: http.StatusOK, Body: `{"data": {}}`},
	} {
		server := fakeupstream.New(test, response)

		_, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1"))
		if nil == err || strings.Contains(err.Error(), "secret-key") {
			test.Errorf("Lookup() of %+v error = %v, want an error without the key", response, err)
		}
	}
}

// TestNewReportsAutonomousSystem checks that the asn is stored as "AS<number>" whichever form
// Shodan sends: text for some hosts, a bare number for others (seen for 165.245.184.215 on
// 2026-10-01), or null.
func TestNewReportsAutonomousSystem(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		body string
		want string
	}{
		{body: `{"asn": "AS45090"}`, want: "AS45090"},
		{body: `{"asn": 14061}`, want: "AS14061"},
		{body: `{"asn": null}`},
		{body: `{}`},
	}

	for _, testCase := range testCases {
		reports, err := newReports([]byte(testCase.body))
		if nil != err {
			test.Fatalf("newReports(%s) error = %v, want nil", testCase.body, err)
		}

		var got Data
		if err := json.Unmarshal(reports[0].Data, &got); nil != err || testCase.want != got.ASN {
			test.Errorf("newReports(%s) asn = (%q, %v), want %q", testCase.body, got.ASN, err, testCase.want)
		}
	}

	for _, body := range []string{`{"asn": -1}`, `{"asn": 1.5}`, `{"asn": [1]}`} {
		if _, err := newReports([]byte(body)); nil == err {
			test.Errorf("newReports(%s) error = nil, want error", body)
		}
	}
}

// FuzzNewReports checks that newReports never panics, and that what it accepts is one report
// with valid data.
func FuzzNewReports(fuzzer *testing.F) {
	fuzzer.Add([]byte(readTestdata(fuzzer, "1.15.76.39.json")))
	fuzzer.Add([]byte(`{"asn": 14061}`))
	fuzzer.Add([]byte(`{"data": [{"port": 443, "transport": "udp"}, {"port": 443, "transport": "tcp", "ssl": null, "http": {}}]}`))

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
