package feodotracker

import (
	"encoding/json/jsontext"
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

// newTestFeed returns a feed that downloads from server.
func newTestFeed(testingContext testing.TB, server *fakeupstream.Server) *Feed {
	testingContext.Helper()

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/downloads/ipblocklist_recommended.json"}

	feed, err := New(config, server.Upstream(testingContext), slog.New(slog.DiscardHandler))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return feed
}

// TestNewRejectsInvalidURL checks that the blocklist must be fetched over https.
func TestNewRejectsInvalidURL(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://example.com/"}, nil, nil); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}
}

// TestFeedCollect checks the request and the sighting made from the recorded blocklist.
func TestFeedCollect(test *testing.T) {
	test.Parallel()

	content, err := os.ReadFile(filepath.Join("testdata", "ipblocklist_recommended.json"))
	if nil != err {
		test.Fatalf("reading fixture: %v", err)
	}

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: string(content)})
	feed := newTestFeed(test, server)

	sightings, err := feed.Collect(test.Context())
	if nil != err {
		test.Fatalf("Collect() error = %v, want nil", err)
	}

	if requests := server.Requests(); 1 != len(requests) || http.MethodGet != requests[0].Method {
		test.Errorf("Collect() sent %+v, want one GET", requests)
	}

	want := []aggregator.Sighting{{
		Address: netip.MustParseAddr("50.16.16.211"),
		Report: aggregator.NewReport("443", []string{"QakBot"}, Data{
			Port:       443,
			Status:     "online",
			Hostname:   new("ec2-50-16-16-211.compute-1.amazonaws.com"),
			ASNumber:   14618,
			ASName:     "AMAZON-AES",
			Country:    "US",
			FirstSeen:  time.Date(2025, 12, 30, 13, 56, 31, 0, time.UTC),
			LastOnline: new(time.Date(2026, 3, 12, 0, 0, 0, 0, time.UTC)),
		}),
	}}
	if diff := cmp.Diff(want, sightings, cmp.Comparer(func(first, second netip.Addr) bool { return first == second })); "" != diff {
		test.Errorf("Collect() mismatch (-want +got):\n%s", diff)
	}
}

// TestFeedCollectErrors checks that a blocklist that can't be downloaded or decoded fails the
// feed.
func TestFeedCollectErrors(test *testing.T) {
	test.Parallel()

	for _, response := range []fakeupstream.Response{
		{Status: http.StatusNotFound, Body: "gone"},
		{Status: http.StatusOK, Body: `{"not": "a list"}`},
	} {
		server := fakeupstream.New(test, response)
		feed := newTestFeed(test, server)

		if _, err := feed.Collect(test.Context()); nil == err {
			test.Errorf("Collect() of %+v error = nil, want error", response)
		}
	}
}

// TestNewSighting checks the entries that are converted and the ones that are refused.
func TestNewSighting(test *testing.T) {
	test.Parallel()

	valid := `{"ip_address": "192.0.2.1", "port": 443, "malware": "QakBot", "first_seen": "2025-12-30 13:56:31"`

	testCases := []struct {
		name  string
		entry string
		// wantErr is part of the error, or "" when the entry must be converted.
		wantErr string
	}{
		{name: "without last_online", entry: valid + `, "last_online": null}`},
		{name: "not an object", entry: `1`, wantErr: "decoding entry"},
		{name: "bad address", entry: `{"ip_address": "x"}`, wantErr: "parsing entry"},
		{name: "bad first_seen", entry: `{"ip_address": "192.0.2.1", "first_seen": "today"}`, wantErr: "first_seen"},
		{name: "bad last_online", entry: valid + `, "last_online": "yesterday"}`, wantErr: "last_online"},
		{name: "no malware family", entry: `{"ip_address": "192.0.2.1", "first_seen": "2025-12-30 13:56:31"}`, wantErr: "no malware family"},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			_, err := newSighting(jsontext.Value(testCase.entry))
			if ("" == testCase.wantErr) != (nil == err) || (nil != err && !strings.Contains(err.Error(), testCase.wantErr)) {
				subtest.Errorf("newSighting(%s) error = %v, want %q", testCase.entry, err, testCase.wantErr)
			}
		})
	}
}

// FuzzNewSighting checks that newSighting never panics, and only returns storable addresses
// with one flag, whatever the entry contains.
func FuzzNewSighting(fuzzer *testing.F) {
	fuzzer.Add([]byte(`{"ip_address": "192.0.2.1", "port": 443, "malware": "QakBot", "first_seen": "2025-12-30 13:56:31", "last_online": "2026-03-12"}`))
	fuzzer.Add([]byte(`{"ip_address": "fe80::1%eth0", "malware": "x"}`))

	fuzzer.Fuzz(func(test *testing.T, rawEntry []byte) {
		sighting, err := newSighting(jsontext.Value(rawEntry))
		if nil != err {
			return // Refusing a malformed entry is allowed; panicking isn't.
		}

		if !sighting.Address.IsValid() || 1 != len(sighting.Report.Flags) {
			test.Errorf("newSighting(%q) = %+v, want a valid address and one flag", rawEntry, sighting)
		}
	})
}
