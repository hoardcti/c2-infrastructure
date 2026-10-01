package otx

import (
	"encoding/json/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

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

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/api/v1/indicators/"}

	enricher, err := New(config, server.Upstream(testingContext), "secret")
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks that the URL must be https and the key set.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://otx.alienvault.com/"}, nil, "secret"); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}

	if _, err := New(aggregator.SourceConfig{URL: "https://otx.alienvault.com/"}, nil, ""); nil == err || !strings.Contains(err.Error(), "key") {
		test.Errorf("New(no key) error = %v, want a key error", err)
	}
}

// TestEnricherLookup checks the request and the report made from a recorded response: pulses
// sorted by ID with their malware families, TLP lower-cased.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "1.117.77.166.json")})

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("1.117.77.166"))
	if nil != err || 1 != len(reports) {
		test.Fatalf("Lookup() = (%v, %v), want one report", reports, err)
	}

	request := server.Requests()[0]
	if "/api/v1/indicators/IPv4/1.117.77.166/general" != request.Path || "secret" != request.Header.Get("X-OTX-API-KEY") {
		test.Errorf("Lookup() sent %+v, want the IPv4 general section with the key header", request)
	}

	var got Data
	if err := json.Unmarshal(reports[0].Data, &got); nil != err {
		test.Fatalf("decoding report data: %v", err)
	}

	cobaltStrikePulse := Pulse{
		ID:              "67764b381db8982f4914295b",
		Name:            "Cobalt Strike Indicators of Compromise (IOC) Feed - PrecisionSec - Tracking 2025",
		Created:         time.Date(2025, 1, 2, 8, 15, 52, 46000000, time.UTC),
		TLP:             "white",
		MalwareFamilies: []string{"Cobalt Strike"},
	}

	isExpected := 9 == got.PulseCount && 2 == len(got.Pulses) && "AS45090 shenzhen tencent computer systems company limited" == got.ASN &&
		"6a88005d764e0d972021269b" == got.Pulses[1].ID && 0 == len(got.Pulses[1].MalwareFamilies)
	if !isExpected {
		test.Errorf("Lookup() data = %+v, want 9 pulses counted and two listed in ID order", got)
	}

	// The pulse's fifteen tags are left out of the comparison to keep the test readable.
	if diff := cmp.Diff(cobaltStrikePulse, got.Pulses[0], cmpopts.IgnoreFields(Pulse{}, "Tags")); "" != diff {
		test.Errorf("Lookup() first pulse mismatch (-want +got):\n%s", diff)
	}
}

// TestEnricherLookupIPv6 checks that an IPv6 address is looked up as an IPv6 indicator.
func TestEnricherLookupIPv6(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: `{"pulse_info": {"count": 0, "pulses": []}}`})

	if _, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("2001:db8::1")); nil != err {
		test.Fatalf("Lookup() error = %v, want nil", err)
	}

	if path := server.Requests()[0].Path; "/api/v1/indicators/IPv6/2001:db8::1/general" != path {
		test.Errorf("Lookup() requested %q, want the IPv6 indicator", path)
	}
}

// TestEnricherLookupErrors checks that a failed request or invalid response fails the lookup.
func TestEnricherLookupErrors(test *testing.T) {
	test.Parallel()

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusForbidden, Body: `{"detail": "Authentication required"}`},
		{Status: http.StatusOK, Body: `{"pulse_info": []}`},
	} {
		server := fakeupstream.New(test, response)

		if _, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil == err {
			test.Errorf("Lookup() of %+v error = nil, want error", response)
		}
	}
}

// TestNewPulseUnparsableTime checks that a creation time in another format is left out rather
// than failing the lookup.
func TestNewPulseUnparsableTime(test *testing.T) {
	test.Parallel()

	if created := newPulse(pulse{Created: "last week"}).Created; !created.IsZero() {
		test.Errorf("newPulse() created = %v, want zero", created)
	}
}

// FuzzNewReports checks that newReports never panics, and that what it accepts is one report
// with valid data.
func FuzzNewReports(fuzzer *testing.F) {
	fuzzer.Add([]byte(readTestdata(fuzzer, "1.117.77.166.json")))
	fuzzer.Add([]byte(`{"pulse_info": {"pulses": [{"id": "b"}, {"id": "a", "created": "x"}]}}`))

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
