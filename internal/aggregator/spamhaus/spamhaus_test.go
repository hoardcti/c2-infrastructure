package spamhaus

import (
	"encoding/json/jsontext"
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

// newTestEnricher returns an enricher that downloads both lists from server.
func newTestEnricher(testingContext testing.TB, server *fakeupstream.Server) *Enricher {
	testingContext.Helper()

	config := aggregator.SourceConfig{
		Name:    SOURCE_NAME,
		URL:     server.URL() + "/drop/drop_v4.json",
		Options: jsontext.Value(`{"ipv6_url": "` + server.URL() + `/drop/drop_v6.json"}`),
	}

	enricher, err := New(config, server.Upstream(testingContext))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return enricher
}

// TestNewRejectsInvalidConfiguration checks every setting New refuses.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	for _, config := range []aggregator.SourceConfig{
		{URL: "http://www.spamhaus.org/drop/drop_v4.json", Options: jsontext.Value(`{"ipv6_url": "https://example.com/"}`)},
		{URL: "https://www.spamhaus.org/drop/drop_v4.json", Options: jsontext.Value(`{"ipv6": "https://example.com/"}`)},
		{URL: "https://www.spamhaus.org/drop/drop_v4.json"},
	} {
		if _, err := New(config, nil); nil == err {
			test.Errorf("New(%+v) error = nil, want error", config)
		}
	}
}

// TestEnricherLookup checks that both lists are downloaded once, on the first lookup, and that
// addresses are matched against them locally.
func TestEnricherLookup(test *testing.T) {
	test.Parallel()

	// The fake answers the IPv4 list first and the IPv6 list second.
	server := fakeupstream.New(
		test,
		fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "drop_v4.json")},
		fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "drop_v6.json")},
	)
	enricher := newTestEnricher(test, server)

	testCases := []struct {
		address  string
		wantCIDR string
	}{
		{address: "1.10.20.30", wantCIDR: "1.10.16.0/20"},
		{address: "192.0.2.1"},
		{address: "2a14:c380:12::1"},
	}

	for _, testCase := range testCases {
		reports, err := enricher.Lookup(test.Context(), netip.MustParseAddr(testCase.address))
		if nil != err {
			test.Fatalf("Lookup(%s) error = %v, want nil", testCase.address, err)
		}

		var want []aggregator.Report
		if "" != testCase.wantCIDR {
			want = []aggregator.Report{aggregator.NewReport(testCase.wantCIDR, nil, Netblock{CIDR: testCase.wantCIDR, SBLID: "SBL256894", RIR: "apnic"})}
		}

		if diff := cmp.Diff(want, reports); "" != diff {
			test.Errorf("Lookup(%s) mismatch (-want +got):\n%s", testCase.address, diff)
		}
	}

	requests := server.Requests()
	if 2 != len(requests) || "/drop/drop_v4.json" != requests[0].Path || "/drop/drop_v6.json" != requests[1].Path {
		test.Errorf("Lookup() sent %+v, want each list downloaded once", requests)
	}
}

// TestEnricherLookupMatchesIPv6 checks that IPv6 addresses are matched against the IPv6 list.
func TestEnricherLookupMatchesIPv6(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(
		test,
		fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "drop_v4.json")},
		fakeupstream.Response{Status: http.StatusOK, Body: readTestdata(test, "drop_v6.json")},
	)

	netblocks, err := parseList([]byte(readTestdata(test, "drop_v6.json")))
	if nil != err {
		test.Fatalf("parsing the IPv6 list: %v", err)
	}

	first := netblocks[0]
	address := first.prefix.Addr()

	reports, err := newTestEnricher(test, server).Lookup(test.Context(), address)
	if nil != err || 1 != len(reports) || first.CIDR != reports[0].Key {
		test.Errorf("Lookup(%s) = (%+v, %v), want a match with %s", address, reports, err, first.CIDR)
	}
}

// TestEnricherLookupLoadFailure checks that a list that can't be downloaded fails every lookup,
// without downloading it again.
func TestEnricherLookupLoadFailure(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusForbidden, Body: "blocked"})
	enricher := newTestEnricher(test, server)

	for range 2 {
		if _, err := enricher.Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil == err || !strings.Contains(err.Error(), "downloading DROP list") {
			test.Errorf("Lookup() error = %v, want a download error", err)
		}
	}

	if 1 != len(server.Requests()) {
		test.Errorf("Lookup() sent %d requests, want 1", len(server.Requests()))
	}
}

// TestParseList checks the lists parseList refuses, and that blank lines and the metadata line
// are skipped.
func TestParseList(test *testing.T) {
	test.Parallel()

	netblocks, err := parseList([]byte("\n{\"cidr\":\"192.0.2.0/24\",\"sblid\":\"SBL1\",\"rir\":\"arin\"}\n\n{\"type\":\"metadata\"}\n"))
	if nil != err || 1 != len(netblocks) || "SBL1" != netblocks[0].SBLID {
		test.Errorf("parseList() = (%+v, %v), want one netblock", netblocks, err)
	}

	testCases := []struct {
		name string
		body string
		// wantErr is part of the error parseList must return.
		wantErr string
	}{
		{name: "not JSON", body: "{\n", wantErr: "decoding line 1"},
		{name: "bad netblock", body: `{"cidr":"192.0.2.0"}`, wantErr: "parsing line 1"},
		{name: "only metadata", body: `{"type":"metadata"}`, wantErr: "no netblocks"},
		{name: "line too long", body: strings.Repeat("x", 70_000), wantErr: "reading list"},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if _, err := parseList([]byte(testCase.body)); nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("parseList() error = %v, want one containing %q", err, testCase.wantErr)
			}
		})
	}

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: `{"type":"metadata"}`})
	if _, err := newTestEnricher(test, server).Lookup(test.Context(), netip.MustParseAddr("192.0.2.1")); nil == err || !strings.Contains(err.Error(), "parsing DROP list") {
		test.Errorf("Lookup() of an empty list error = %v, want a parsing error", err)
	}
}

// FuzzParseList checks that parseList never panics, and that every netblock it returns is a
// valid prefix.
func FuzzParseList(fuzzer *testing.F) {
	fuzzer.Add(readTestdata(fuzzer, "drop_v4.json"))
	fuzzer.Add(readTestdata(fuzzer, "drop_v6.json"))
	fuzzer.Add(`{"cidr":"192.0.2.1/24"}`)

	fuzzer.Fuzz(func(test *testing.T, body string) {
		netblocks, err := parseList([]byte(body))
		if nil != err {
			return // Refusing a malformed list is allowed; panicking isn't.
		}

		for _, netblock := range netblocks {
			if !netblock.prefix.IsValid() {
				test.Errorf("parseList(%q) returned invalid netblock %+v", body, netblock)
			}
		}
	})
}
