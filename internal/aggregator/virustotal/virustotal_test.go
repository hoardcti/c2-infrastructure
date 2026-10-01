package virustotal

import (
	"encoding/json/v2"
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

// newTestEnricher returns an enricher that queries server with the key "secret".
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server) *Enricher {
	testingContext.Helper()

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/api/v3/ip_addresses/"}

	enricher, err := New(config, server.Upstream(testingContext), "secret")
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks that the URL must be https and the key set.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://www.virustotal.com/"}, nil, "secret"); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}

	if _, err := New(aggregator.SourceConfig{URL: "https://www.virustotal.com/"}, nil, ""); nil == err || !strings.Contains(err.Error(), "key") {
		test.Errorf("New(no key) error = %v, want a key error", err)
	}
}

// TestEnricherLookup checks that the key is sent in the x-apikey header, and the report made
// from a recorded response: only flagging vendors are kept, sorted, and partner notes lose
// their details and timestamps.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "1.15.76.39.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("1.15.76.39"))
	if nil != err || 1 != len(reports) {
		test.Fatalf("Lookup() = (%v, %v), want one report", reports, err)
	}

	requests := server.Requests()
	if "/api/v3/ip_addresses/1.15.76.39" != requests[0].Path || "secret" != requests[0].Header.Get("X-Apikey") {
		test.Errorf("Lookup() sent %+v, want the address path with the x-apikey header", requests[0])
	}

	var got Data
	if err := json.Unmarshal(reports[0].Data, &got); nil != err {
		test.Fatalf("decoding report data: %v", err)
	}

	want := Data{
		ASOwner:                  "Shenzhen Tencent Computer Systems Company Limited",
		ASN:                      45090,
		Network:                  "1.14.0.0/15",
		Country:                  "CN",
		Continent:                "AS",
		RegionalInternetRegistry: "APNIC",
		Reputation:               -12,
		AnalysisStats:            AnalysisStats{Malicious: 9, Suspicious: 3, Undetected: 32, Harmless: 47},
		FlaggingVendors: []Verdict{
			{Vendor: "ADMINUSLabs", Category: "malicious", Result: "malicious"},
			{Vendor: "AlphaSOC", Category: "malicious", Result: "malware"},
			{Vendor: "Criminal IP", Category: "malicious", Result: "malicious"},
			{Vendor: "alphaMountain.ai", Category: "suspicious", Result: "suspicious"},
		},
		TotalVotes: Votes{Malicious: 2},
		Tags:       []string{},
		CrowdsourcedContext: []PartnerNote{
			{Source: "Cluster25", Title: "Activity related to COBALTSTRIKE", Severity: "high"},
			{Source: "Hunt.io Intelligence", Title: "Malicious activity", Severity: "high"},
		},
	}
	if diff := cmp.Diff(want, got); "" != diff {
		test.Errorf("Lookup() data mismatch (-want +got):\n%s", diff)
	}

	if strings.Contains(string(reports[0].Data), "whois") || strings.Contains(string(reports[0].Data), "last_analysis_date") {
		test.Errorf("Lookup() data = %s, want no WHOIS or analysis dates", reports[0].Data)
	}
}

// TestEnricherLookupNotFoundAndErrors checks that an unknown address gives no reports, and a
// failed request or invalid response fails the lookup.
func TestEnricherLookupNotFoundAndErrors(test *testing.T) {
	test.Parallel()

	notFound := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusNotFound, Body: `{"error": {"code": "NotFoundError"}}`})
	if reports, err := newTestEnricher(test, notFound).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil != err || 0 != len(reports) {
		test.Errorf("Lookup() of an unknown address = (%v, %v), want no reports and no error", reports, err)
	}

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusUnauthorized, Body: `{"error": {"code": "WrongCredentialsError"}}`},
		{Status: http.StatusOK, Body: `{"data": []}`},
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
	fuzzer.Add([]byte(`{"data": {"attributes": {"last_analysis_results": {"a": {"category": "malicious"}}}}}`))

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
