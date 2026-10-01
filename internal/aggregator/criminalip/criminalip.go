// Package criminalip is the Criminal IP C2 Daily Feed: a daily sample of 50 C2 servers that
// Criminal IP publishes as a dated CSV file on GitHub.
//
// Each row becomes an observation keyed by the open port, so a new scan of the same server
// with a different score shows up as a new observation. The feed needs no key.
//
// It's a package of its own, imported only by the command, because it hides the feed's column
// layout and file naming from the rest of the program (GO-PKG-004, reason 3), like every
// source.
package criminalip

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// Criminal IP's daily C2 feed.
const (
	// SOURCE_NAME names the Criminal IP feed in sources.json and in every record.
	SOURCE_NAME = "criminalip"
	// MAX_RESPONSE_BYTES bounds a daily file, which holds about 50 rows.
	MAX_RESPONSE_BYTES = 4 << 20
	// COLUMN_COUNT is the number of columns in each row: IP address, malware family, port,
	// score, country and scan time.
	COLUMN_COUNT = 6
	// SCAN_TIME_LAYOUT matches the scan time column, such as "2026-09-24 18:21:09", in UTC.
	SCAN_TIME_LAYOUT = "2006-01-02 15:04:05"
	// YEAR_LAYOUT formats the four-digit year in a file name, such as "2026".
	YEAR_LAYOUT = "2006"
	// MONTH_LAYOUT formats the zero-padded month in a file name, such as "05".
	MONTH_LAYOUT = "01"
	// DAY_LAYOUT formats the zero-padded day of the month in a file name, such as "09".
	DAY_LAYOUT = "02"
)

// Options are the feed's own settings in sources.json.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type Options struct {
	// FileFormat is the name of each day's file, where YYYY, MM and DD stand for today's year,
	// month and day in UTC, such as "YYYY-MM-DD.csv".
	FileFormat string `json:"file_format"`
}

// Feed downloads today's file of the Criminal IP feed. Build one with New.
type Feed struct {
	// baseURL is the directory the daily files are published in.
	baseURL *url.URL
	// fileFormat is Options.FileFormat.
	fileFormat string
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// logger receives skipped-row messages.
	logger *slog.Logger
	// now returns the current time, which picks the file; tests replace it with a fixed clock.
	now func() time.Time
}

// New builds the Criminal IP feed from its sources.json entry. The entry's url is the base URL
// of the raw files, and its options must give a file_format.
func New(
	config aggregator.SourceConfig,
	upstream *aggregator.Upstream,
	logger *slog.Logger,
	options ...Option,
) (*Feed, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	var feedOptions Options
	if err := aggregator.DecodeOptions(config.Options, &feedOptions); nil != err {
		return nil, fmt.Errorf("checking options: %w", err)
	}

	if "" == feedOptions.FileFormat {
		return nil, errors.New("options need a file_format")
	}

	feed := &Feed{
		baseURL:    endpoint,
		fileFormat: feedOptions.FileFormat,
		upstream:   upstream,
		logger:     logger,
		now:        time.Now,
	}
	for _, option := range options {
		option(feed)
	}

	return feed, nil
}

// Option configures a Feed built by New.
type Option func(*Feed)

// WithClock sets the clock that picks today's file. By default it's time.Now.
func WithClock(now func() time.Time) Option {
	return func(feed *Feed) { feed.now = now }
}

// Data is what a Criminal IP observation stores about one C2 server.
type Data struct {
	// Port is the open port Criminal IP found, as the feed wrote it.
	Port string `json:"port"`
	// Score is Criminal IP's inbound and outbound risk score, such as "Critical/Critical".
	Score string `json:"score"`
	// Country is the address's two-letter country code, as the feed wrote it.
	Country string `json:"country"`
	// ScanTime is when Criminal IP scanned the address.
	ScanTime time.Time `json:"scan_time"`
}

// Collect downloads today's file and returns one sighting per row. A file that isn't
// published yet (404 Not Found) gives no sightings rather than an error, because the feed is
// published once a day and the aggregator runs every hour. Malformed rows are skipped with a
// warning.
func (feed *Feed) Collect(ctx context.Context) ([]aggregator.Sighting, error) {
	// The file name is FileFormat with YYYY, MM and DD replaced by today's date, so
	// "YYYY-MM-DD.csv" becomes, for example, "2026-05-19.csv".
	today := feed.now().UTC()
	fileName := strings.NewReplacer(
		"YYYY", today.Format(YEAR_LAYOUT),
		"MM", today.Format(MONTH_LAYOUT),
		"DD", today.Format(DAY_LAYOUT),
	).Replace(feed.fileFormat)

	// JoinPath escapes the file name, so it can't change the rest of the URL.
	fileURL := feed.baseURL.JoinPath(fileName).String()

	body, err := feed.upstream.Fetch(ctx, aggregator.Request{Method: http.MethodGet, URL: fileURL}, MAX_RESPONSE_BYTES)

	if aggregator.IsNotFound(err) {
		feed.logger.InfoContext(ctx, "daily file not published yet", "source", SOURCE_NAME, "file_name", fileName)

		return nil, nil
	}

	if nil != err {
		return nil, fmt.Errorf("downloading %q: %w", fileName, err)
	}

	rows := aggregator.ReadCSVRows(ctx, feed.logger, SOURCE_NAME, body, COLUMN_COUNT)

	return aggregator.ConvertEntries(ctx, feed.logger, SOURCE_NAME, rows, newSighting), nil
}

// newSighting converts one row into a sighting. row has exactly COLUMN_COUNT columns.
func newSighting(row []string) (aggregator.Sighting, error) {
	rawAddress, family, port, score, country, rawScanTime := row[0], row[1], row[2], row[3], row[4], row[5]

	address, err := aggregator.ParseAddress(rawAddress)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing row: %w", err)
	}

	scanTime, err := time.ParseInLocation(SCAN_TIME_LAYOUT, rawScanTime, time.UTC)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing scan time %q: %w", rawScanTime, err)
	}

	report := aggregator.NewReport(port, []string{family}, Data{
		Port:     port,
		Score:    score,
		Country:  country,
		ScanTime: scanTime,
	})

	// A row without a malware family wouldn't say what the C2 server belongs to.
	if 0 == len(report.Flags) {
		return aggregator.Sighting{}, fmt.Errorf("row for %q has no malware family", address)
	}

	return aggregator.Sighting{Address: address, Report: report}, nil
}
