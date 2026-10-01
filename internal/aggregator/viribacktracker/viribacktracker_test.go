package viribacktracker

import (
	"bytes"
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

// newTestFeed returns a feed that downloads from server, logging warnings to the returned
// buffer.
func newTestFeed(testingContext testing.TB, server *fakeupstream.Server) (*Feed, *bytes.Buffer) {
	testingContext.Helper()

	var logs bytes.Buffer

	config := aggregator.SourceConfig{Name: SOURCE_NAME, URL: server.URL() + "/last30.php"}

	feed, err := New(config, server.Upstream(testingContext), slog.New(slog.NewTextHandler(&logs, nil)))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	return feed, &logs
}

// TestNewRejectsInvalidURL checks that the feed must be fetched over https.
func TestNewRejectsInvalidURL(test *testing.T) {
	test.Parallel()

	if _, err := New(aggregator.SourceConfig{URL: "http://example.com/"}, nil, nil); nil == err {
		test.Error("New(http URL) error = nil, want error")
	}
}

// TestFeedCollect checks the sightings made from the recorded feed: one per row, keyed by the
// panel URL.
func TestFeedCollect(test *testing.T) {
	test.Parallel()

	content, err := os.ReadFile(filepath.Join("testdata", "last30.csv"))
	if nil != err {
		test.Fatalf("reading fixture: %v", err)
	}

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: string(content)})
	feed, _ := newTestFeed(test, server)

	sightings, err := feed.Collect(test.Context())
	if nil != err || 5 != len(sightings) {
		test.Fatalf("Collect() = (%d sightings, %v), want 5", len(sightings), err)
	}

	panelURL := "http://47.105.68.108:8082/login/index"
	want := aggregator.Sighting{
		Address: netip.MustParseAddr("47.105.68.108"),
		Report: aggregator.NewReport(panelURL, []string{"Vshell"}, Data{
			PanelURL:  panelURL,
			FirstSeen: time.Date(2026, 9, 26, 0, 0, 0, 0, time.UTC),
		}),
	}
	if diff := cmp.Diff(want, sightings[0], cmp.Comparer(func(first, second netip.Addr) bool { return first == second })); "" != diff {
		test.Errorf("Collect() first sighting mismatch (-want +got):\n%s", diff)
	}
}

// TestFeedCollectSkipsBadRows checks that malformed rows are skipped with a warning and the
// rest are kept, and that a failed download fails the feed.
func TestFeedCollectSkipsBadRows(test *testing.T) {
	test.Parallel()

	body := "Family,URL,IP,FirstSeen\n" +
		"Vshell,http://192.0.2.1/,192.0.2.1,7-3-2026\n" +
		"Vshell,http://192.0.2.2/,not an address,7-3-2026\n" +
		"Vshell,http://192.0.2.3/,192.0.2.3,March\n" +
		",http://192.0.2.4/,192.0.2.4,7-3-2026\n" +
		"too,few\n"

	server := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusOK, Body: body})
	feed, logs := newTestFeed(test, server)

	sightings, err := feed.Collect(test.Context())
	if nil != err || 1 != len(sightings) {
		test.Errorf("Collect() = (%v, %v), want only the first row", sightings, err)
	}

	for _, want := range []string{"parsing row", "first-seen date", "no malware family", "malformed CSV row"} {
		if !strings.Contains(logs.String(), want) {
			test.Errorf("Collect() logs = %q, want them to mention %q", logs.String(), want)
		}
	}

	failing := fakeupstream.New(test, fakeupstream.Response{Status: http.StatusBadRequest})
	failingFeed, _ := newTestFeed(test, failing)

	if _, err := failingFeed.Collect(test.Context()); nil == err {
		test.Error("Collect() of a failed download error = nil, want error")
	}
}

// FuzzNewSighting checks that newSighting never panics, and only returns storable addresses
// with one flag, whatever the row contains.
func FuzzNewSighting(fuzzer *testing.F) {
	fuzzer.Add("Vshell", "http://192.0.2.1/", "192.0.2.1", "26-09-2026")
	fuzzer.Add("", "", "::1", "1-1-2026")

	fuzzer.Fuzz(func(test *testing.T, family, panelURL, address, firstSeen string) {
		sighting, err := newSighting([]string{family, panelURL, address, firstSeen})
		if nil != err {
			return // Refusing a malformed row is allowed; panicking isn't.
		}

		if !sighting.Address.IsValid() || 1 != len(sighting.Report.Flags) {
			test.Errorf("newSighting() = %+v, want a valid address and one flag", sighting)
		}
	})
}
