// Package aggregator fetches the C2 feeds configured in sources.json, converts each feed's
// entries into payloads and stores one JSON file per IP address.
//
// The package is internal: only this module can import it, so its exported names, including
// the SCREAMING_SNAKE_CASE constants, aren't a public API.
package aggregator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Aggregator defaults and limits.
const (
	// PROJECT_URL tells upstream operators where the requests come from.
	PROJECT_URL = "https://github.com/hoardcti/c2-infrastructure"
	// DEFAULT_USER_AGENT identifies the program to upstreams when WithUserAgent isn't used.
	DEFAULT_USER_AGENT = "hoardcti-c2-infrastructure (+" + PROJECT_URL + ")"
	// MAX_FEED_BYTES bounds a downloaded feed file. The largest feed, Feodo Tracker's
	// blocklist, has never been more than a few MiB.
	MAX_FEED_BYTES = 64 << 20
	// REDACTED replaces a secret wherever it would otherwise be printed or logged.
	REDACTED = "[REDACTED]"
)

// Layouts of the date parts in a Git source's file name, such as "2026" for 2026-05-09.
const (
	// YEAR_LAYOUT formats the four-digit year, such as "2026".
	YEAR_LAYOUT = "2006"
	// MONTH_LAYOUT formats the zero-padded month, such as "05".
	MONTH_LAYOUT = "01"
	// DAY_LAYOUT formats the zero-padded day of the month, such as "09".
	DAY_LAYOUT = "02"
)

// errNoExtractor is returned by New for an enabled source whose name has no extractor.
var errNoExtractor = errors.New("no extractor for this source name")

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

// Aggregator collects payloads from every enabled source and stores them. Build one with New.
type Aggregator struct {
	// store receives every payload.
	store *Store
	// httpClient sends every upstream request.
	httpClient *http.Client
	// logger receives progress and skipped-entry warnings.
	logger *slog.Logger
	// now returns the current time; tests replace it with a fixed clock.
	now func() time.Time
	// userAgent is sent with every upstream request.
	userAgent string
	// abusechAPIKey authenticates requests to abuse.ch's ThreatFox API.
	abusechAPIKey APIKey
	// feedExtractors maps the name of a Git, JSON or CSV source to the function that parses
	// its downloaded body.
	feedExtractors map[string]feedExtractor
	// apiExtractors maps the name of an API source to the function that queries it.
	apiExtractors map[string]apiExtractor
	// jobs holds one entry per enabled source, in the order Run processes them.
	jobs []sourceJob
}

// New builds an Aggregator that saves payloads from every enabled source in sources to store,
// sending requests with httpClient. It checks every enabled source before returning: each must
// have a known name and valid https URLs, and API sources must have a query. The ThreatFox
// source also needs WithAbusechAPIKey.
//
// options ...Option accepts any number of options, including none; inside New it's a slice.
func New(
	sources Sources,
	store *Store,
	httpClient *http.Client,
	options ...Option,
) (*Aggregator, error) {
	if nil == store || nil == httpClient {
		return nil, errors.New("a store and an HTTP client are required")
	}

	// Defaults first, then the options, so a later option wins.
	aggregator := &Aggregator{
		store:      store,
		httpClient: httpClient,
		logger:     slog.New(slog.DiscardHandler),
		now:        time.Now,
		userAgent:  DEFAULT_USER_AGENT,
	}
	for _, option := range options {
		option(aggregator)
	}

	// Each extractor is a method value: it remembers aggregator, so it can use the client,
	// logger and clock.
	aggregator.feedExtractors = map[string]feedExtractor{
		CRIMINALIP_SOURCE_NAME:      aggregator.extractCriminalIP,
		FEODOTRACKER_SOURCE_NAME:    aggregator.extractFeodoTracker,
		VIRIBACKTRACKER_SOURCE_NAME: aggregator.extractViriBackTracker,
	}
	aggregator.apiExtractors = map[string]apiExtractor{
		THREATFOX_SOURCE_NAME: aggregator.extractThreatFox,
	}

	// Check every source and report every problem at once. A nil slice is a valid empty list:
	// append allocates it on first use.
	var problems []error

	for _, source := range sources.enabled() {
		job, err := aggregator.newJob(source)
		if nil != err {
			problems = append(problems, fmt.Errorf("source %q: %w", source.Name, err))

			continue
		}

		aggregator.jobs = append(aggregator.jobs, job)
	}

	if 0 != len(problems) {
		return nil, fmt.Errorf("invalid sources: %w", errors.Join(problems...))
	}

	return aggregator, nil
}

// Run processes every enabled source and returns how many payloads were stored. A source
// that fails doesn't stop the others: every failure is returned, joined together. Cancelling
// ctx stops the run before the next source or payload.
//
// ctx carries the caller's cancellation signal (Ctrl+C or SIGTERM); ctx.Err() is non-nil once
// it has been cancelled.
func (aggregator *Aggregator) Run(ctx context.Context) (int, error) {
	storedCount := 0

	var failures []error

	for _, job := range aggregator.jobs {
		sourceName := job.source.Name

		// Stop before starting another source once the run has been cancelled.
		if nil != ctx.Err() {
			stopErr := fmt.Errorf("stopping before source %q: %w", sourceName, ctx.Err())
			failures = append(failures, stopErr)

			break
		}

		// Count what was stored even when the source then fails part-way through.
		sourceStoredCount, err := aggregator.processSource(ctx, job)
		storedCount += sourceStoredCount

		if nil != err {
			failures = append(failures, fmt.Errorf("processing source %q: %w", sourceName, err))
		}
	}

	return storedCount, errors.Join(failures...)
}

// newJob checks an enabled source and pairs it with the function that collects its payloads.
func (aggregator *Aggregator) newJob(source Source) (sourceJob, error) {
	switch source.kind {
	case SOURCE_KIND_GIT:
		return aggregator.newGitJob(source)
	case SOURCE_KIND_JSON, SOURCE_KIND_CSV:
		return aggregator.newFeedJob(source)
	case SOURCE_KIND_API:
		return aggregator.newAPIJob(source)
	}

	return sourceJob{}, fmt.Errorf("unknown source kind %q", source.kind)
}

// newGitJob checks a Git source and returns a job that downloads today's file.
func (aggregator *Aggregator) newGitJob(source Source) (sourceJob, error) {
	// The second value, ok, is false when the name isn't in the map.
	extract, ok := aggregator.feedExtractors[source.Name]
	if !ok {
		return sourceJob{}, errNoExtractor
	}

	if err := validateUpstreamURL(source.URLRaw); nil != err {
		return sourceJob{}, fmt.Errorf("checking url_raw: %w", err)
	}

	if "" == source.FileFormat {
		return sourceJob{}, errors.New("file_format is required")
	}

	// The function literal is a closure: it keeps using source and extract from this call.
	collect := func(ctx context.Context) ([]Payload, error) {
		return aggregator.collectGitFile(ctx, source, extract)
	}

	return sourceJob{source: source, collect: collect}, nil
}

// newFeedJob checks a JSON or CSV source and returns a job that downloads its URL.
func (aggregator *Aggregator) newFeedJob(source Source) (sourceJob, error) {
	extract, ok := aggregator.feedExtractors[source.Name]
	if !ok {
		return sourceJob{}, errNoExtractor
	}

	if err := validateUpstreamURL(source.URL); nil != err {
		return sourceJob{}, fmt.Errorf("checking url: %w", err)
	}

	collect := func(ctx context.Context) ([]Payload, error) {
		return aggregator.collectFeed(ctx, source.URL, extract)
	}

	return sourceJob{source: source, collect: collect}, nil
}

// newAPIJob checks an API source and returns a job that queries it.
func (aggregator *Aggregator) newAPIJob(source Source) (sourceJob, error) {
	extract, ok := aggregator.apiExtractors[source.Name]
	if !ok {
		return sourceJob{}, errNoExtractor
	}

	if err := validateUpstreamURL(source.URL); nil != err {
		return sourceJob{}, fmt.Errorf("checking url: %w", err)
	}

	if "" == source.Query.Query || source.Query.Limit < 1 {
		return sourceJob{}, errors.New("query needs a query and a limit of at least 1")
	}

	// ThreatFox rejects requests without an Auth-Key, so fail now rather than on every run.
	if THREATFOX_SOURCE_NAME == source.Name && "" == aggregator.abusechAPIKey {
		return sourceJob{}, errors.New("the ABUSECH_API_KEY environment variable is required")
	}

	collect := func(ctx context.Context) ([]Payload, error) {
		return extract(ctx, source)
	}

	return sourceJob{source: source, collect: collect}, nil
}

// processSource collects one source's payloads and stores them, returning how many were
// stored.
func (aggregator *Aggregator) processSource(ctx context.Context, job sourceJob) (int, error) {
	payloads, err := job.collect(ctx)
	if nil != err {
		return 0, err
	}

	storedCount, err := aggregator.saveAll(ctx, payloads)
	aggregator.logger.InfoContext(
		ctx,
		"source processed",
		"source", job.source.Name,
		"payload_count", len(payloads),
		"stored_count", storedCount,
	)

	return storedCount, err
}

// saveAll stores every payload and returns how many were stored. A payload that can't be
// stored doesn't stop the others: every failure is returned, joined together. It stops early
// if ctx is cancelled.
func (aggregator *Aggregator) saveAll(ctx context.Context, payloads []Payload) (int, error) {
	storedCount := 0

	var failures []error

	for _, payload := range payloads {
		// Every file already written is complete, so stopping here leaves no partial output.
		if nil != ctx.Err() {
			failures = append(failures, fmt.Errorf("saving payloads: %w", ctx.Err()))

			break
		}

		if err := aggregator.store.SavePayload(payload); nil != err {
			failures = append(failures, fmt.Errorf("saving payload for %q: %w", payload.IP, err))

			continue
		}

		storedCount++
	}

	return storedCount, errors.Join(failures...)
}

// collectGitFile downloads today's file of a Git source and parses it with extract.
func (aggregator *Aggregator) collectGitFile(
	ctx context.Context,
	source Source,
	extract feedExtractor,
) ([]Payload, error) {
	// The file name is FileFormat with YYYY, MM and DD replaced by today's date, so
	// "YYYY-MM-DD.csv" becomes, for example, "2026-05-19.csv".
	today := aggregator.now().UTC()
	fileName := strings.NewReplacer(
		"YYYY", today.Format(YEAR_LAYOUT),
		"MM", today.Format(MONTH_LAYOUT),
		"DD", today.Format(DAY_LAYOUT),
	).Replace(source.FileFormat)

	// JoinPath escapes the file name, so it can't change the rest of the URL.
	fileURL, err := url.JoinPath(source.URLRaw, fileName)
	if nil != err {
		return nil, fmt.Errorf("building file URL: %w", err)
	}

	return aggregator.collectFeed(ctx, fileURL, extract)
}

// collectFeed downloads feedURL and parses the body with extract.
func (aggregator *Aggregator) collectFeed(
	ctx context.Context,
	feedURL string,
	extract feedExtractor,
) ([]Payload, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
	if nil != err {
		return nil, fmt.Errorf("building request: %w", err)
	}

	body, err := aggregator.send(request, MAX_FEED_BYTES)
	if nil != err {
		return nil, fmt.Errorf("downloading %q: %w", feedURL, err)
	}

	return extract(ctx, bytes.NewReader(body))
}

// Option configures an Aggregator built by New.
type Option func(*Aggregator)

// WithLogger sets the logger that receives progress and skipped-entry warnings. By default
// nothing is logged.
func WithLogger(logger *slog.Logger) Option {
	return func(aggregator *Aggregator) { aggregator.logger = logger }
}

// WithUserAgent sets the User-Agent header sent with every upstream request.
func WithUserAgent(userAgent string) Option {
	return func(aggregator *Aggregator) { aggregator.userAgent = userAgent }
}

// WithAbusechAPIKey sets the abuse.ch Auth-Key the ThreatFox source sends.
func WithAbusechAPIKey(apiKey APIKey) Option {
	return func(aggregator *Aggregator) { aggregator.abusechAPIKey = apiKey }
}

// feedExtractor parses a downloaded feed body into payloads.
type feedExtractor func(ctx context.Context, body io.Reader) ([]Payload, error)

// apiExtractor queries an API source and returns the payloads it reports.
type apiExtractor func(ctx context.Context, source Source) ([]Payload, error)

// sourceJob pairs an enabled source with the function that collects its payloads.
type sourceJob struct {
	// source is the enabled source.
	source Source
	// collect fetches the source and returns its payloads.
	collect func(ctx context.Context) ([]Payload, error)
}

// validateUpstreamURL checks that rawURL is an absolute https URL. Upstream data travels only
// over TLS, so nobody on the network path can tamper with the intelligence we publish.
func validateUpstreamURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if nil != err {
		return fmt.Errorf("parsing URL: %w", err)
	}

	isAbsoluteHTTPS := "https" == parsedURL.Scheme && "" != parsedURL.Host
	if !isAbsoluteHTTPS {
		return fmt.Errorf("URL %q isn't an absolute https URL", rawURL)
	}

	return nil
}
