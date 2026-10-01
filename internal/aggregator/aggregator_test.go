package aggregator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-cmp/cmp"
)

// testSchedule lets an enricher look up every address in a test, once a day.
var testSchedule = Schedule{MaxLookups: 100, RefreshAfter: 24 * time.Hour, MaxDuration: time.Hour}

// fakeFeed is a feed that returns fixed sightings, or an error.
type fakeFeed struct {
	// sightings are returned by every Collect.
	sightings []Sighting
	// err is returned by every Collect, when set.
	err error
}

// Collect returns the fixed sightings or error. Having this method makes fakeFeed a Feed.
func (feed fakeFeed) Collect(_ context.Context) ([]Sighting, error) {
	return feed.sightings, feed.err
}

// fakeEnricher is an enricher whose answers come from a function, and which records every
// address it's asked about. The aggregator looks addresses up one at a time, so it needs no
// mutex.
type fakeEnricher struct {
	// lookup answers each lookup.
	lookup func(ctx context.Context, address netip.Addr) ([]Report, error)
	// addresses holds every address looked up, in order.
	addresses []netip.Addr
}

// Lookup records address and answers with lookup. Having this method makes *fakeEnricher an
// Enricher.
func (enricher *fakeEnricher) Lookup(ctx context.Context, address netip.Addr) ([]Report, error) {
	enricher.addresses = append(enricher.addresses, address)

	return enricher.lookup(ctx, address)
}

// newTestAggregator returns an Aggregator with a fixed clock that stores in store, built with
// options. Its logs, at every level, go to the returned buffer.
func newTestAggregator(testingContext testing.TB, store *Store, options ...Option) (*Aggregator, *bytes.Buffer) {
	testingContext.Helper()

	var logs bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	aggregator, err := New(store, append(options, WithLogger(logger))...)
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	aggregator.now = func() time.Time { return fixedTime }

	return aggregator, &logs
}

// newSighting returns a sighting of address with one report.
func newSighting(address, key, data string, flags ...string) Sighting {
	return Sighting{Address: netip.MustParseAddr(address), Report: newTestReport(key, data, flags...)}
}

// TestAPIKeyRedacts checks that an API key never appears when printed or logged.
func TestAPIKeyRedacts(test *testing.T) {
	test.Parallel()

	key := APIKey("secret-key")

	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("test", "key", key)

	for _, output := range []string{key.String(), fmt.Sprintf("%v %s", key, key), logs.String()} {
		if strings.Contains(output, "secret-key") || !strings.Contains(output, REDACTED) {
			test.Errorf("output %q shows the key, want it redacted", output)
		}
	}
}

// TestNewRejectsInvalidSources checks that every problem with the sources is reported by New,
// before any work starts.
func TestNewRejectsInvalidSources(test *testing.T) {
	test.Parallel()

	if _, err := New(nil); nil == err {
		test.Error("New(nil store) error = nil, want error")
	}

	store := newTestStore(test)
	enricher := &fakeEnricher{}

	testCases := []struct {
		name    string
		options []Option
		// wantErr is part of the error New must return.
		wantErr string
	}{
		{name: "empty name", options: []Option{WithFeed("", fakeFeed{})}, wantErr: `source name ""`},
		{
			name:    "name used twice",
			options: []Option{WithFeed("shodan", fakeFeed{}), WithEnricher("shodan", enricher, testSchedule)},
			wantErr: `source name "shodan" is empty or used twice`,
		},
		{
			name:    "schedule without lookups",
			options: []Option{WithEnricher("shodan", enricher, Schedule{RefreshAfter: time.Hour, MaxDuration: time.Hour})},
			wantErr: "schedule must be positive",
		},
		{
			name:    "schedule without a time budget",
			options: []Option{WithEnricher("shodan", enricher, Schedule{MaxLookups: 1, RefreshAfter: time.Hour})},
			wantErr: "schedule must be positive",
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if _, err := New(store, testCase.options...); nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("New() error = %v, want one containing %q", err, testCase.wantErr)
			}
		})
	}
}

// TestAggregatorRunCombinesSources checks a whole run: feeds add addresses, several sources
// report the same address under their own names, enrichers look up every address including
// the new ones, and a failing feed doesn't stop the others.
func TestAggregatorRunCombinesSources(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	enricher := &fakeEnricher{lookup: func(_ context.Context, address netip.Addr) ([]Report, error) {
		return []Report{newTestReport("", `{"looked_up":"`+address.String()+`"}`)}, nil
	}}

	aggregator, logs := newTestAggregator(
		test,
		store,
		WithFeed("threatfox", fakeFeed{sightings: []Sighting{
			newSighting("192.0.2.1", "1", `{"port":443}`, "sliver"),
			newSighting("192.0.2.1", "2", `{"port":8443}`, "sliver"),
			newSighting("192.0.2.2", "3", `{"port":80}`, "cobalt strike"),
		}}),
		WithFeed("broken", fakeFeed{err: errors.New("upstream down")}),
		WithFeed("feodotracker", fakeFeed{sightings: []Sighting{newSighting("192.0.2.1", "443", `{"port":443}`, "qakbot")}}),
		WithEnricher("shodan", enricher, testSchedule),
	)

	writtenCount, err := aggregator.Run(test.Context())
	if nil == err || !strings.Contains(err.Error(), `processing feed "broken": collecting: upstream down`) {
		test.Errorf("Run() error = %v, want only the broken feed's failure", err)
	}

	// Two addresses from threatfox, one from feodotracker and two from shodan.
	if 5 != writtenCount {
		test.Errorf("Run() wrote %d files, want 5", writtenCount)
	}

	record := readStoredRecord(test, store, "192.0.2.1")

	wantObservationCounts := map[string]int{"threatfox": 2, "feodotracker": 1, "shodan": 1}
	for source, wantCount := range wantObservationCounts {
		if wantCount != len(record.Sources[source].Observations) {
			test.Errorf("source %q has %d observations, want %d", source, len(record.Sources[source].Observations), wantCount)
		}
	}

	if diff := cmp.Diff([]string{"qakbot", "sliver"}, record.Flags); "" != diff {
		test.Errorf("record flags mismatch (-want +got):\n%s", diff)
	}

	wantAddresses := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}
	if diff := cmp.Diff(wantAddresses, enricher.addresses, recordComparison); "" != diff {
		test.Errorf("enricher addresses mismatch (-want +got):\n%s", diff)
	}

	for _, want := range []string{
		`msg="feed processed" source=threatfox sighting_count=3 address_count=2 written_count=2`,
		`msg="enricher processed" source=shodan due_count=2 lookup_count=2 written_count=2 out_of_time=false`,
	} {
		if !strings.Contains(logs.String(), want) {
			test.Errorf("Run() logs = %q, want them to contain %q", logs.String(), want)
		}
	}

	// A second run reports the same things, so only last_observed and last_checked could
	// change, and the clock is fixed: nothing is written.
	if writtenCount, _ := aggregator.Run(test.Context()); 0 != writtenCount {
		test.Errorf("repeated Run() wrote %d files, want 0", writtenCount)
	}
}

// TestAggregatorRunEnricherFailures checks how lookup failures are handled: recorded on the
// address and skipped, or stopping the enricher when every later lookup would fail too.
func TestAggregatorRunEnricherFailures(test *testing.T) {
	test.Parallel()

	addresses := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"}
	transientErr := errors.New("timeout")

	testCases := []struct {
		name string
		// failing returns the error for a lookup of address, or nil.
		failing func(address netip.Addr) error
		// wantLookups is how many addresses are looked up before the enricher stops.
		wantLookups int
		// wantRecordedErrors is how many addresses get a last_error.
		wantRecordedErrors int
		// wantStopReason is part of the reason the enricher must stop early, or "" when it
		// must carry on.
		wantStopReason string
		// wantRunSuccess is true when every failure is an expected rejection, which doesn't
		// fail the run.
		wantRunSuccess bool
	}{
		{
			name: "one address fails",
			failing: func(address netip.Addr) error {
				if netip.MustParseAddr("192.0.2.3") == address {
					return transientErr
				}

				return nil
			},
			wantLookups: 7, wantRecordedErrors: 1,
		},
		{
			name:        "rejected key stops at once",
			failing:     func(netip.Addr) error { return &StatusError{StatusCode: http.StatusUnauthorized} },
			wantLookups: 1, wantStopReason: "the API key was rejected",
		},
		{
			// Shodan's answer to a free key asking for a host.
			name: "plan without access stops at once",
			failing: func(netip.Addr) error {
				return fmt.Errorf("querying Shodan: %w", &StatusError{StatusCode: http.StatusForbidden, Snippet: "Requires membership or higher to access"})
			},
			wantLookups: 1, wantStopReason: "upgrade the plan or disable the source in sources.json",
		},
		{
			name: "used-up quota stops at once",
			failing: func(netip.Addr) error {
				return fmt.Errorf("querying: %w", &StatusError{StatusCode: http.StatusTooManyRequests})
			},
			wantLookups: 1, wantStopReason: "lower max_lookups",
		},
		{
			name:        "repeated failures stop the enricher",
			failing:     func(netip.Addr) error { return transientErr },
			wantLookups: MAX_CONSECUTIVE_LOOKUP_FAILURES, wantRecordedErrors: MAX_CONSECUTIVE_LOOKUP_FAILURES,
			wantStopReason: "5 lookups in a row failed",
		},
		{
			// Rejections are about each address alone, so they never stop the enricher.
			name:        "rejected addresses don't stop the enricher",
			failing:     func(netip.Addr) error { return &StatusError{StatusCode: http.StatusUnprocessableEntity} },
			wantLookups: 7, wantRecordedErrors: 7, wantRunSuccess: true,
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			store := newTestStore(subtest)
			enricher := &fakeEnricher{lookup: func(_ context.Context, address netip.Addr) ([]Report, error) {
				return nil, testCase.failing(address)
			}}

			// Each address is first added by a feed, so it's in the dataset.
			aggregator, logs := newTestAggregator(subtest, store, WithFeed("feed", sightingsFeed(addresses...)), WithEnricher("shodan", enricher, testSchedule))

			_, err := aggregator.Run(subtest.Context())
			checkEnricherFailure(subtest, err, logs.String(), testCase.wantStopReason, testCase.wantRunSuccess)

			if testCase.wantLookups != len(enricher.addresses) {
				subtest.Errorf("Run() looked up %d addresses, want %d", len(enricher.addresses), testCase.wantLookups)
			}

			if recordedErrors := countRecordedErrors(subtest, store, "shodan", addresses); testCase.wantRecordedErrors != recordedErrors {
				subtest.Errorf("Run() recorded %d errors, want %d", recordedErrors, testCase.wantRecordedErrors)
			}
		})
	}
}

// checkEnricherFailure checks the outcome of a run whose enricher failed: an error with
// wantStopReason when the enricher had to stop, no error but a logged warning when every
// failure was an expected rejection, and otherwise an error without a stop.
func checkEnricherFailure(testingContext testing.TB, err error, logs, wantStopReason string, wantRunSuccess bool) {
	testingContext.Helper()

	if wantRunSuccess {
		if nil != err || !strings.Contains(logs, `msg="lookup rejected" source=shodan`) {
			testingContext.Errorf("Run() = %v with logs %q, want no error and the rejections logged", err, logs)
		}

		return
	}

	isStopped := nil != err && strings.Contains(err.Error(), "stopping the source for the rest of this run")
	if nil == err || ("" != wantStopReason) != isStopped || !strings.Contains(err.Error(), wantStopReason) {
		testingContext.Errorf("Run() error = %v, want a failure with stop reason %q", err, wantStopReason)
	}
}

// sightingsFeed returns a feed that reports each address with one flagged report.
func sightingsFeed(addresses ...string) fakeFeed {
	var sightings []Sighting
	for _, address := range addresses {
		sightings = append(sightings, newSighting(address, "1", `{}`, "sliver"))
	}

	return fakeFeed{sightings: sightings}
}

// countRecordedErrors returns how many of addresses have a last_error from sourceName.
func countRecordedErrors(testingContext testing.TB, store *Store, sourceName string, addresses []string) int {
	testingContext.Helper()

	recordedErrors := 0

	for _, address := range addresses {
		if "" != readStoredRecord(testingContext, store, address).Sources[sourceName].LastError.Message {
			recordedErrors++
		}
	}

	return recordedErrors
}

// TestAggregatorRunEnricherTimeBudget checks that an enricher stops quietly once its time
// budget is used up, without recording the interrupted lookup. Time is controlled by
// testing/synctest, so the minutes take no real time.
func TestAggregatorRunEnricherTimeBudget(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(test *testing.T) {
		store := newTestStore(test)

		// Each lookup takes a minute, unless its context ends first.
		enricher := &fakeEnricher{lookup: func(ctx context.Context, _ netip.Addr) ([]Report, error) {
			timer := time.NewTimer(time.Minute)
			defer timer.Stop()

			select {
			case <-timer.C:
				return nil, nil
			case <-ctx.Done():
				return nil, fmt.Errorf("waiting: %w", ctx.Err())
			}
		}}

		schedule := testSchedule
		schedule.MaxDuration = 150 * time.Second

		feed := sightingsFeed("192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4")
		aggregator, logs := newTestAggregator(test, store, WithFeed("feed", feed), WithEnricher("slow", enricher, schedule))

		if _, err := aggregator.Run(test.Context()); nil != err {
			test.Errorf("Run() error = %v, want nil: a used-up budget isn't a failure", err)
		}

		// Two lookups finish; the third is cut short and the fourth never starts.
		if 3 != len(enricher.addresses) || !strings.Contains(logs.String(), "lookup_count=3 written_count=2 out_of_time=true") {
			test.Errorf("Run() looked up %v with logs %q, want two finished lookups and the budget reported", enricher.addresses, logs.String())
		}

		if _, wasChecked := readStoredRecord(test, store, "192.0.2.3").Sources["slow"]; wasChecked {
			test.Error("the interrupted lookup was stored, want it left for the next run")
		}
	})
}

// TestAggregatorRunCancelled checks that a cancelled run stops before the next source,
// address or lookup, and reports the cancellation.
func TestAggregatorRunCancelled(test *testing.T) {
	test.Parallel()

	sightings := []Sighting{newSighting("192.0.2.1", "1", `{}`, "sliver"), newSighting("192.0.2.2", "1", `{}`, "sliver")}

	test.Run("before the feeds", func(subtest *testing.T) {
		subtest.Parallel()

		ctx, cancel := context.WithCancel(subtest.Context())
		cancel()

		aggregator, _ := newTestAggregator(subtest, newTestStore(subtest), WithFeed("feed", fakeFeed{sightings: sightings}))
		if writtenCount, err := aggregator.Run(ctx); !errors.Is(err, context.Canceled) || 0 != writtenCount {
			subtest.Errorf("Run() = (%d, %v), want nothing written and %v", writtenCount, err, context.Canceled)
		}
	})

	test.Run("while storing a feed", func(subtest *testing.T) {
		subtest.Parallel()

		ctx, cancel := context.WithCancel(subtest.Context())
		feed := cancellingFeed{cancel: cancel, sightings: sightings}

		aggregator, _ := newTestAggregator(subtest, newTestStore(subtest), WithFeed("feed", feed))
		if writtenCount, err := aggregator.Run(ctx); !errors.Is(err, context.Canceled) || 0 != writtenCount {
			subtest.Errorf("Run() = (%d, %v), want nothing written and %v", writtenCount, err, context.Canceled)
		}
	})

	test.Run("during the enrichers", func(subtest *testing.T) {
		subtest.Parallel()

		ctx, cancel := context.WithCancel(subtest.Context())
		first := &fakeEnricher{lookup: func(context.Context, netip.Addr) ([]Report, error) {
			cancel()

			return nil, nil
		}}
		second := &fakeEnricher{}

		aggregator, _ := newTestAggregator(
			subtest,
			newTestStore(subtest),
			WithFeed("feed", fakeFeed{sightings: sightings}),
			WithEnricher("first", first, testSchedule),
			WithEnricher("second", second, testSchedule),
		)

		_, err := aggregator.Run(ctx)
		if !errors.Is(err, context.Canceled) || 1 != len(first.addresses) || 0 != len(second.addresses) {
			subtest.Errorf("Run() error = %v after %d and %d lookups, want %v after one lookup", err, len(first.addresses), len(second.addresses), context.Canceled)
		}
	})
}

// cancellingFeed is a feed that cancels the run while returning its sightings.
type cancellingFeed struct {
	// cancel cancels the run's context.
	cancel context.CancelFunc
	// sightings are returned by Collect.
	sightings []Sighting
}

// Collect cancels the run and returns the sightings.
func (feed cancellingFeed) Collect(_ context.Context) ([]Sighting, error) {
	feed.cancel()

	return feed.sightings, nil
}

// TestAggregatorRunStoreFailures checks that records that can't be stored are reported without
// stopping the other addresses or sources.
func TestAggregatorRunStoreFailures(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)

	// The enricher breaks the file of the address it's looking up, so storing the result fails.
	enricher := &fakeEnricher{lookup: func(_ context.Context, address netip.Addr) ([]Report, error) {
		if netip.MustParseAddr("192.0.2.1") == address {
			writeStoreFile(test, store, addressFileName(address), []byte("{"))
		}

		return nil, nil
	}}

	aggregator, _ := newTestAggregator(
		test,
		store,
		WithFeed("feed", fakeFeed{sightings: []Sighting{
			{Report: newTestReport("1", `{}`, "sliver")}, // The zero address can't be stored.
			newSighting("192.0.2.1", "1", `{}`, "sliver"),
			newSighting("192.0.2.2", "1", `{}`, "sliver"),
		}}),
		WithEnricher("shodan", enricher, testSchedule),
	)

	writtenCount, err := aggregator.Run(test.Context())

	for _, want := range []string{`storing sightings of "invalid IP"`, `storing lookup of "192.0.2.1"`} {
		if nil == err || !strings.Contains(err.Error(), want) {
			test.Errorf("Run() error = %v, want it to contain %q", err, want)
		}
	}

	// Both feed sightings and the lookup of 192.0.2.2 are stored.
	if 3 != writtenCount {
		test.Errorf("Run() wrote %d files, want 3", writtenCount)
	}
}

// TestAggregatorRunIndexFailure checks that a stored file that can't be indexed is reported,
// and the other addresses are still enriched.
func TestAggregatorRunIndexFailure(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	writeStoreFile(test, store, addressFileName(netip.MustParseAddr("192.0.2.9")), []byte("{"))

	enricher := &fakeEnricher{lookup: func(context.Context, netip.Addr) ([]Report, error) { return nil, nil }}
	aggregator, _ := newTestAggregator(
		test,
		store,
		WithFeed("feed", fakeFeed{sightings: []Sighting{newSighting("192.0.2.1", "1", `{}`, "sliver")}}),
		WithEnricher("shodan", enricher, testSchedule),
	)

	_, err := aggregator.Run(test.Context())
	if nil == err || !strings.Contains(err.Error(), "indexing records") || 1 != len(enricher.addresses) {
		test.Errorf("Run() = %v after looking up %v, want the index failure and 192.0.2.1 enriched", err, enricher.addresses)
	}
}

// TestSelectDueAddresses checks which addresses are due and their order: never-tried
// addresses first, newest first_seen first, then the longest-waiting, up to the budget.
func TestSelectDueAddresses(test *testing.T) {
	test.Parallel()

	schedule := Schedule{MaxLookups: 4, RefreshAfter: 24 * time.Hour, MaxDuration: time.Hour}
	entry := func(address string, firstSeen time.Time, lastAttempt time.Time) indexEntry {
		attempts := map[string]time.Time{}
		if !lastAttempt.IsZero() {
			attempts["shodan"] = lastAttempt
		}

		return indexEntry{address: netip.MustParseAddr(address), firstSeen: firstSeen, lastAttempts: attempts}
	}

	entries := []indexEntry{
		entry("192.0.2.1", fixedTime.Add(-48*time.Hour), fixedTime.Add(-30*time.Hour)), // Due, waiting 30 hours.
		entry("192.0.2.2", fixedTime.Add(-48*time.Hour), fixedTime.Add(-time.Hour)),    // Checked recently.
		entry("192.0.2.3", fixedTime.Add(-time.Hour), time.Time{}),                     // Never tried, newest.
		entry("192.0.2.4", fixedTime.Add(-48*time.Hour), time.Time{}),                  // Never tried, older.
		entry("192.0.2.5", fixedTime.Add(-48*time.Hour), fixedTime.Add(-24*time.Hour)), // Due, exactly 24 hours.
		entry("192.0.2.6", fixedTime.Add(-48*time.Hour), fixedTime.Add(-26*time.Hour)), // Due, but over budget.
		entry("192.0.2.7", fixedTime.Add(-48*time.Hour), time.Time{}),                  // Never tried, ties with .4.
	}

	got := selectDueAddresses(entries, "shodan", schedule, fixedTime)

	want := []netip.Addr{
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.4"),
		netip.MustParseAddr("192.0.2.7"),
		netip.MustParseAddr("192.0.2.1"),
	}
	if diff := cmp.Diff(want, got, recordComparison); "" != diff {
		test.Errorf("selectDueAddresses() mismatch (-want +got):\n%s", diff)
	}

	if due := selectDueAddresses(nil, "shodan", schedule, fixedTime); 0 != len(due) {
		test.Errorf("selectDueAddresses(nil) = %v, want none", due)
	}
}

// TestCompareBooleans checks that false sorts before true.
func TestCompareBooleans(test *testing.T) {
	test.Parallel()

	if 0 != compareBooleans(true, true) || -1 != compareBooleans(false, true) || 1 != compareBooleans(true, false) {
		test.Error("compareBooleans() doesn't order false before true")
	}
}
