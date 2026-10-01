// Package aggregator collects C2 intelligence from many sources and keeps one JSON record per
// IP address, holding every observation each source has ever reported.
//
// Sources come in two kinds. A Feed lists C2 servers and so adds addresses to the dataset. An
// Enricher looks up addresses already in the dataset, within a per-run budget, and adds what
// it knows about them. Each source lives in its own package under this directory and builds
// its reports with this package's helpers (NewReport, Upstream, ParseAddress); the command
// wires the enabled ones together.
//
// The package is internal: only this module can import it, so its exported names, including
// the SCREAMING_SNAKE_CASE constants, aren't a public API.
package aggregator

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"
)

// Aggregator defaults and limits.
const (
	// PROJECT_URL tells upstream operators where the requests come from.
	PROJECT_URL = "https://github.com/hoardcti/c2-infrastructure"
	// DEFAULT_USER_AGENT identifies the program to upstreams when WithUserAgent isn't used.
	DEFAULT_USER_AGENT = "hoardcti-c2-infrastructure (+" + PROJECT_URL + ")"
	// REDACTED replaces a secret wherever it would otherwise be printed or logged.
	REDACTED = "[REDACTED]"
	// MAX_CONSECUTIVE_LOOKUP_FAILURES stops an enricher for the rest of the run after this
	// many lookups in a row have failed, so an upstream outage doesn't use up the whole run.
	MAX_CONSECUTIVE_LOOKUP_FAILURES = 5
)

// APIKey is a secret credential. It redacts itself when logged or printed, so it can't leak
// through logs or error messages.
type APIKey string

// LogValue implements slog.LogValuer so the key never appears in logs. Go has no "implements"
// keyword: having a method with this name and signature is enough.
func (key APIKey) LogValue() slog.Value {
	return slog.StringValue(REDACTED)
}

// String keeps the key out of fmt output, including %v and %s.
func (key APIKey) String() string {
	return REDACTED
}

// Feed is a source that lists C2 servers.
type Feed interface {
	// Collect returns every sighting the feed currently lists. Malformed entries are skipped;
	// an error means the feed as a whole couldn't be read.
	Collect(ctx context.Context) ([]Sighting, error)
}

// Enricher is a source that describes an address already in the dataset.
type Enricher interface {
	// Lookup returns what the source reports about address, or no reports if it knows
	// nothing about it. An error means the lookup itself failed.
	Lookup(ctx context.Context, address netip.Addr) ([]Report, error)
}

// Sighting is one address listed by a feed, with what the feed says about it.
type Sighting struct {
	// Address is the listed IP address.
	Address netip.Addr
	// Report is what the feed says about it.
	Report Report
}

// Schedule spreads an enricher's lookups over runs so it stays within its upstream's quota.
type Schedule struct {
	// MaxLookups caps the lookups in one run.
	MaxLookups int
	// RefreshAfter is how long to wait before looking an address up again.
	RefreshAfter time.Duration
	// MaxDuration caps the time spent on the enricher in one run.
	MaxDuration time.Duration
}

// Aggregator runs every configured source and stores what they report. Build one with New.
type Aggregator struct {
	// store keeps the records.
	store *Store
	// logger receives progress and skipped-entry warnings.
	logger *slog.Logger
	// now returns the current time; tests replace it with a fixed clock.
	now func() time.Time
	// feeds run first, in order.
	feeds []feedSource
	// enrichers run after the feeds, in order.
	enrichers []enricherSource
}

// feedSource is a feed with the name its observations are stored under.
type feedSource struct {
	// name is the source's name in sources.json.
	name string
	// feed collects the sightings.
	feed Feed
}

// enricherSource is an enricher with its name and schedule.
type enricherSource struct {
	// name is the source's name in sources.json.
	name string
	// enricher looks addresses up.
	enricher Enricher
	// schedule limits the lookups.
	schedule Schedule
}

// New builds an Aggregator that stores what its sources report in store. Sources are added
// with WithFeed and WithEnricher; every name must be unique, because it keys the source's
// history in each record.
//
// options ...Option accepts any number of options, including none; inside New it's a slice.
func New(store *Store, options ...Option) (*Aggregator, error) {
	if nil == store {
		return nil, errors.New("a store is required")
	}

	// Defaults first, then the options, so a later option wins.
	aggregator := &Aggregator{
		store:  store,
		logger: slog.New(slog.DiscardHandler),
		now:    time.Now,
	}
	for _, option := range options {
		option(aggregator)
	}

	// Check every source and report every problem at once.
	var problems []error

	seenNames := map[string]bool{}

	for _, name := range aggregator.sourceNames() {
		if "" == name || seenNames[name] {
			problems = append(problems, fmt.Errorf("source name %q is empty or used twice", name))
		}

		seenNames[name] = true
	}

	for _, source := range aggregator.enrichers {
		schedule := source.schedule
		if schedule.MaxLookups < 1 || schedule.RefreshAfter <= 0 || schedule.MaxDuration <= 0 {
			problems = append(problems, fmt.Errorf("source %q: schedule must be positive", source.name))
		}
	}

	if 0 != len(problems) {
		return nil, fmt.Errorf("invalid sources: %w", errors.Join(problems...))
	}

	return aggregator, nil
}

// Option configures an Aggregator built by New.
type Option func(*Aggregator)

// WithLogger sets the logger that receives progress and skipped-entry warnings. By default
// nothing is logged.
func WithLogger(logger *slog.Logger) Option {
	return func(aggregator *Aggregator) { aggregator.logger = logger }
}

// WithFeed adds a feed whose observations are stored under name.
func WithFeed(name string, feed Feed) Option {
	return func(aggregator *Aggregator) {
		aggregator.feeds = append(aggregator.feeds, feedSource{name: name, feed: feed})
	}
}

// WithEnricher adds an enricher whose observations are stored under name, looking addresses
// up as schedule allows.
func WithEnricher(name string, enricher Enricher, schedule Schedule) Option {
	return func(aggregator *Aggregator) {
		aggregator.enrichers = append(aggregator.enrichers, enricherSource{
			name:     name,
			enricher: enricher,
			schedule: schedule,
		})
	}
}

// sourceNames returns the name of every source, feeds first.
func (aggregator *Aggregator) sourceNames() []string {
	names := make([]string, 0, len(aggregator.feeds)+len(aggregator.enrichers))

	for _, source := range aggregator.feeds {
		names = append(names, source.name)
	}

	for _, source := range aggregator.enrichers {
		names = append(names, source.name)
	}

	return names
}

// Run processes every feed, then every enricher, and returns how many record files it wrote.
// A source that fails doesn't stop the others: every failure is returned, joined together.
// Cancelling ctx stops the run before the next source, address or lookup; every file already
// written is complete.
//
// ctx carries the caller's cancellation signal (Ctrl+C or SIGTERM); ctx.Err() is non-nil once
// it has been cancelled.
func (aggregator *Aggregator) Run(ctx context.Context) (int, error) {
	writtenCount := 0

	var failures []error

	// Feeds first, so the enrichers also look up the addresses they add.
	for _, source := range aggregator.feeds {
		if nil != ctx.Err() {
			return writtenCount, errors.Join(append(failures, ctx.Err())...)
		}

		sourceWrittenCount, err := aggregator.runFeed(ctx, source)
		writtenCount += sourceWrittenCount

		if nil != err {
			failures = append(failures, fmt.Errorf("processing feed %q: %w", source.name, err))
		}
	}

	// Indexing also upgrades files in an older format, so it runs even without enrichers. A
	// file that can't be indexed is reported, and the rest are still enriched.
	entries, err := aggregator.store.index(ctx, aggregator.sourceNames())
	if nil != err {
		failures = append(failures, fmt.Errorf("indexing records: %w", err))
	}

	for _, source := range aggregator.enrichers {
		if nil != ctx.Err() {
			return writtenCount, errors.Join(append(failures, ctx.Err())...)
		}

		sourceWrittenCount, err := aggregator.runEnricher(ctx, source, entries)
		writtenCount += sourceWrittenCount

		if nil != err {
			failures = append(failures, fmt.Errorf("processing enricher %q: %w", source.name, err))
		}
	}

	return writtenCount, errors.Join(failures...)
}

// runFeed collects one feed and stores its sightings, one record update per address. It
// returns how many files it wrote.
func (aggregator *Aggregator) runFeed(ctx context.Context, source feedSource) (int, error) {
	sightings, err := source.feed.Collect(ctx)
	if nil != err {
		return 0, fmt.Errorf("collecting: %w", err)
	}

	// Group the reports by address, keeping the feed's order, so each file is written once.
	var addresses []netip.Addr

	reportsByAddress := map[netip.Addr][]Report{}

	for _, sighting := range sightings {
		// The comma-ok form: isKnown is false when the map has no entry for the address yet.
		// The blank identifier _ discards the entry itself.
		if _, isKnown := reportsByAddress[sighting.Address]; !isKnown {
			addresses = append(addresses, sighting.Address)
		}

		reportsByAddress[sighting.Address] = append(reportsByAddress[sighting.Address], sighting.Report)
	}

	// Every report in this run is stamped with the same moment, to the second.
	checkedAt := aggregator.now().UTC().Truncate(time.Second)
	writtenCount := 0

	var failures []error

	for _, address := range addresses {
		// Every file already written is complete, so stopping here leaves no partial output.
		if nil != ctx.Err() {
			failures = append(failures, fmt.Errorf("storing sightings: %w", ctx.Err()))

			break
		}

		// The function literal is a closure: it uses address, source and checkedAt from here.
		isWritten, err := aggregator.store.Update(address, func(record *Record) {
			record.addReports(source.name, reportsByAddress[address], checkedAt)
		})
		if nil != err {
			failures = append(failures, fmt.Errorf("storing sightings of %q: %w", address, err))

			continue
		}

		if isWritten {
			writtenCount++
		}
	}

	aggregator.logger.InfoContext(
		ctx,
		"feed processed",
		"source", source.name,
		"sighting_count", len(sightings),
		"address_count", len(addresses),
		"written_count", writtenCount,
	)

	return writtenCount, errors.Join(failures...)
}

// runEnricher looks up the addresses that are due for one enricher and stores the results. It
// returns how many files it wrote.
//
// What happens after a failed lookup depends on what the failure means (see ErrUnauthorised and
// the other kinds in upstream.go):
//
//   - A rejected key (ErrUnauthorised), a plan that doesn't allow the lookup (ErrForbidden) or
//     a used-up quota (ErrRateLimited) would make every later lookup fail too, so the enricher
//     stops for the rest of the run, with the reason and what to do about it. Nothing is
//     recorded on the address, because the failure isn't about it.
//   - A request the upstream rejected for this address alone (ErrRejected) is recorded as the
//     source's last_error on the address, and the next address is looked up.
//   - Any other failure, such as an unavailable upstream or an invalid response, is recorded on
//     the address too, and stops the enricher once MAX_CONSECUTIVE_LOOKUP_FAILURES happen in a
//     row, so an outage doesn't use up the whole run.
//
// Once the enricher's time budget is used up it stops quietly, leaving the remaining addresses
// due for the next run.
func (aggregator *Aggregator) runEnricher(
	ctx context.Context,
	source enricherSource,
	entries []indexEntry,
) (int, error) {
	now := aggregator.now().UTC().Truncate(time.Second)
	dueAddresses := selectDueAddresses(entries, source.name, source.schedule, now)

	// budgetCtx is cancelled when the run is, or when the enricher's time budget is used up.
	// cancel releases its timer; defer calls it when runEnricher returns.
	budgetCtx, cancel := context.WithTimeout(ctx, source.schedule.MaxDuration)
	defer cancel()

	var (
		failures            []error
		writtenCount        int
		lookupCount         int
		consecutiveFailures int
	)

	for _, address := range dueAddresses {
		lookupCount++
		reports, lookupErr := source.enricher.Lookup(budgetCtx, address)

		// A lookup cut short by the budget or a cancelled run says nothing about the address,
		// and every later lookup would be cut short too.
		if nil != budgetCtx.Err() {
			break
		}

		isWritten, err := aggregator.storeLookup(source.name, address, reports, lookupErr)
		if nil != err {
			failures = append(failures, err)
		}

		if isWritten {
			writtenCount++
		}

		if nil == lookupErr {
			consecutiveFailures = 0

			continue
		}

		failures = append(failures, fmt.Errorf("looking up %q: %w", address, lookupErr))

		// A rejection is about this address alone, so it says nothing about the upstream's health.
		if !errors.Is(lookupErr, ErrRejected) {
			consecutiveFailures++
		}

		if reason := stopReason(lookupErr, consecutiveFailures); "" != reason {
			failures = append(failures, fmt.Errorf("stopping the source for the rest of this run: %s", reason))

			break
		}
	}

	// A cancelled run is a failure; a used-up time budget is expected and only reported.
	isOutOfTime := nil == ctx.Err() && nil != budgetCtx.Err()
	if nil != ctx.Err() {
		failures = append(failures, fmt.Errorf("looking up addresses: %w", ctx.Err()))
	}

	aggregator.logger.InfoContext(
		ctx,
		"enricher processed",
		"source", source.name,
		"due_count", len(dueAddresses),
		"lookup_count", lookupCount,
		"written_count", writtenCount,
		"out_of_time", isOutOfTime,
	)

	return writtenCount, errors.Join(failures...)
}

// storeLookup stores the result of looking address up with the source named sourceName: the
// reports, or lookupErr as the source's last_error. A failure that isn't about this address,
// such as a rejected key, isn't stored. It reports whether the record was written.
func (aggregator *Aggregator) storeLookup(
	sourceName string,
	address netip.Addr,
	reports []Report,
	lookupErr error,
) (bool, error) {
	if stopsEnricher(lookupErr) {
		return false, nil
	}

	checkedAt := aggregator.now().UTC().Truncate(time.Second)

	// The function literal is a closure: it uses the lookup's result from storeLookup.
	isWritten, err := aggregator.store.Update(address, func(record *Record) {
		if nil != lookupErr {
			record.recordFailure(sourceName, lookupErr.Error(), checkedAt)

			return
		}

		record.addReports(sourceName, reports, checkedAt)
	})
	if nil != err {
		return false, fmt.Errorf("storing lookup of %q: %w", address, err)
	}

	return isWritten, nil
}

// stopsEnricher reports whether err will make every later lookup fail too: the upstream
// rejected the key, the key's plan doesn't allow the lookup, or a quota is used up.
func stopsEnricher(err error) bool {
	return errors.Is(err, ErrUnauthorised) || errors.Is(err, ErrForbidden) || errors.Is(err, ErrRateLimited)
}

// stopReason returns why an enricher must stop after the lookup error err, the
// consecutiveFailures-th failure in a row, with what the operator can do about it; or "" if it
// can carry on.
func stopReason(err error, consecutiveFailures int) string {
	switch {
	case errors.Is(err, ErrUnauthorised):
		return "the API key was rejected; check the key in the environment (see KEY.md)"
	case errors.Is(err, ErrForbidden):
		return "the API key's plan doesn't allow these lookups; upgrade the plan or disable the source in sources.json (see KEY.md)"
	case errors.Is(err, ErrRateLimited):
		return "its rate limit or quota is used up; lower max_lookups or requests_per_minute in sources.json (see KEY.md)"
	case MAX_CONSECUTIVE_LOOKUP_FAILURES <= consecutiveFailures:
		return fmt.Sprintf("%d lookups in a row failed", consecutiveFailures)
	}

	return ""
}

// selectDueAddresses returns the addresses an enricher should look up in this run, at most
// schedule.MaxLookups of them. An address is due if the source never tried it, or last tried
// it at least schedule.RefreshAfter ago. Addresses never tried come first, newest first_seen
// first, so new C2 servers are enriched quickly; then the longest-waiting addresses.
func selectDueAddresses(
	entries []indexEntry,
	sourceName string,
	schedule Schedule,
	now time.Time,
) []netip.Addr {
	refreshBefore := now.Add(-schedule.RefreshAfter)

	var due []indexEntry

	for _, entry := range entries {
		lastAttempt, wasAttempted := entry.lastAttempts[sourceName]
		if !wasAttempted || !lastAttempt.After(refreshBefore) {
			due = append(due, entry)
		}
	}

	// SortFunc orders by the comparison function, which returns a negative number when first
	// sorts before second. cmp.Or returns its first non-zero argument, so later comparisons
	// only break ties.
	slices.SortFunc(due, func(first, second indexEntry) int {
		firstAttempt, firstWasAttempted := first.lastAttempts[sourceName]
		secondAttempt, secondWasAttempted := second.lastAttempts[sourceName]

		return cmp.Or(
			compareBooleans(firstWasAttempted, secondWasAttempted),
			second.firstSeen.Compare(first.firstSeen),
			firstAttempt.Compare(secondAttempt),
			first.address.Compare(second.address),
		)
	})

	addresses := make([]netip.Addr, 0, min(len(due), schedule.MaxLookups))
	for _, entry := range due[:min(len(due), schedule.MaxLookups)] {
		addresses = append(addresses, entry.address)
	}

	return addresses
}

// compareBooleans orders false before true.
func compareBooleans(first, second bool) int {
	switch {
	case first == second:
		return 0
	case second:
		return -1
	default:
		return 1
	}
}
