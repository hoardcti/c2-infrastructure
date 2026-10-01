package criminalip

import (
	"bytes"
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

// fixedTime is the clock reading of every test feed: the day of the recorded file. It's never
// changed.
var fixedTime = time.Date(2026, 9, 24, 23, 0, 0, 0, time.UTC)

// newTestFeed returns a feed that downloads from server on fixedTime's day, logging at every
// level to the returned buffer.
func newTestFeed(testingContext testing.TB, server *fakeupstream.Server) (*Feed, *bytes.Buffer) {
	testingContext.Helper()

	var logs bytes.Buffer

	config := aggregator.SourceConfig{
		Name:    SOURCE_NAME,
		URL:     server.URL() + "/feed/",
		Options: jsontext.Value(`{"file_format": "YYYY-MM-DD.csv"}`),
	}
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	feed, err := New(config, server.Upstream(testingContext), logger, WithClock(func() time.Time { return fixedTime }))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return feed, &logs
}

// TestNewRejectsInvalidConfiguration checks every setting New refuses.
func TestNewRejectsInvalidConfiguration(test *testing.T) {
	test.Parallel()

	for _, config := range []aggregator.SourceConfig{
		{URL: "http://example.com/", Options: jsontext.Value(`{"file_format": "x"}`)},
		{URL: "https://example.com/", Options: jsontext.Value(`{"file_name": "x"}`)},
		{URL: "https://example.com/"},
	} {
		if _, err := New(config, nil, nil); nil == err {
			test.Errorf("New(%+v) error = nil, want error", config)
		}
	}

	// The default clock is the real one.
	feed, err := New(aggregator.SourceConfig{URL: "https://example.com/", Options: jsontext.Value(`{"file_format": "x"}`)}, nil, nil)
	if nil != err || time.Since(feed.now()) > time.Minute {
		test.Errorf("New() = (%+v, %v), want the real clock", feed, err)
	}
}

// TestFeedCollect checks that today's file is requested and each row becomes a sighting keyed
// by its port.
func TestFeedCollect(test *testing.T) {
	test.Parallel()

	content, err := os.ReadFile(filepath.Join("testdata", "2026-09-24.csv"))
	if nil != err {
		test.Fatalf("reading fixture: %v", err)
	}

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: string(content)})
	feed, _ := newTestFeed(test, server)

	sightings, err := feed.Collect(test.Context())
	if nil != err || 5 != len(sightings) {
		test.Fatalf("Collect() = (%d sightings, %v), want 5", len(sightings), err)
	}

	if requests := server.Requests(); "/feed/2026-09-24.csv" != requests[0].Path {
		test.Errorf("Collect() requested %q, want today's file", requests[0].Path)
	}

	want := aggregator.Sighting{
		Address: netip.MustParseAddr("35.172.12.146"),
		Report: aggregator.NewReport("443", []string{"c2_meshagent"}, Data{
			Port:     "443",
			Score:    "Critical/Critical",
			Country:  "us",
			ScanTime: time.Date(2026, 9, 24, 18, 21, 9, 0, time.UTC),
		}),
	}
	if diff := cmp.Diff(want, sightings[0], cmp.Comparer(func(first, second netip.Addr) bool { return first == second })); "" != diff {
		test.Errorf("Collect() first sighting mismatch (-want +got):\n%s", diff)
	}
}

// TestFeedCollectUnpublishedFile checks that a file that isn't published yet gives no
// sightings and no error, but other failures fail the feed.
func TestFeedCollectUnpublishedFile(test *testing.T) {
	test.Parallel()

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusNotFound, Body: "404: Not Found"})
	feed, logs := newTestFeed(test, server)

	if sightings, err := feed.Collect(test.Context()); nil != err || 0 != len(sightings) {
		test.Errorf("Collect() of a missing file = (%v, %v), want no sightings and no error", sightings, err)
	}

	if !strings.Contains(logs.String(), `msg="daily file not published yet"`) {
		test.Errorf("Collect() logs = %q, want the missing file reported", logs.String())
	}

	failing := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusForbidden})
	failingFeed, _ := newTestFeed(test, failing)

	if _, err := failingFeed.Collect(test.Context()); nil == err {
		test.Error("Collect() of a forbidden file error = nil, want error")
	}
}

// TestNewSighting checks the rows that are refused.
func TestNewSighting(test *testing.T) {
	test.Parallel()

	for _, row := range [][]string{
		{"not an address", "c2", "443", "High", "us", "2026-09-24 18:21:09"},
		{"192.0.2.1", "c2", "443", "High", "us", "yesterday"},
		{"192.0.2.1", "", "443", "High", "us", "2026-09-24 18:21:09"},
	} {
		if _, err := newSighting(row); nil == err {
			test.Errorf("newSighting(%q) error = nil, want error", row)
		}
	}
}

// FuzzNewSighting checks that newSighting never panics, and only returns storable addresses
// with one flag, whatever the row contains.
func FuzzNewSighting(fuzzer *testing.F) {
	fuzzer.Add("35.172.12.146", "c2_meshagent", "443", "Critical/Critical", "us", "2026-09-24 18:21:09")

	fuzzer.Fuzz(func(test *testing.T, address, family, port, score, country, scanTime string) {
		sighting, err := newSighting([]string{address, family, port, score, country, scanTime})
		if nil != err {
			return // Refusing a malformed row is allowed; panicking isn't.
		}

		if !sighting.Address.IsValid() || 1 != len(sighting.Report.Flags) {
			test.Errorf("newSighting() = %+v, want a valid address and one flag", sighting)
		}
	})
}
