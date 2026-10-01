// Package viribacktracker is the ViriBack C2 tracker feed: C2 panels seen in the last 30 days.
//
// Each row becomes an observation keyed by the panel's URL, so a family relabelled by ViriBack
// shows up as a new observation next to the old one. The feed needs no key.
//
// It's a package of its own, imported only by the command, because it hides the feed's column
// layout from the rest of the program (GO-PKG-004, reason 3), like every source.
package viribacktracker

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The ViriBack C2 tracker feed.
const (
	// SOURCE_NAME names the ViriBack feed in sources.json and in every record.
	SOURCE_NAME = "viribacktracker"
	// MAX_RESPONSE_BYTES bounds the feed, which lists a few thousand panels at most.
	MAX_RESPONSE_BYTES = 16 << 20
	// COLUMN_COUNT is the number of columns in each row: malware family, panel URL, IP address
	// and first-seen date.
	COLUMN_COUNT = 4
	// DATE_LAYOUT matches ViriBack's day-month-year dates, such as "26-09-2026" or "7-3-2026":
	// the day and month may be unpadded.
	DATE_LAYOUT = "2-1-2006"
)

// Feed downloads the ViriBack feed. Build one with New.
type Feed struct {
	// url is the feed's CSV download.
	url string
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// logger receives skipped-row messages.
	logger *slog.Logger
}

// New builds the ViriBack feed from its sources.json entry.
func New(
	config aggregator.SourceConfig,
	upstream *aggregator.Upstream,
	logger *slog.Logger,
) (*Feed, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	return &Feed{url: endpoint.String(), upstream: upstream, logger: logger}, nil
}

// Data is what a ViriBack observation stores about one C2 panel.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to name the
// field's JSON key.
type Data struct {
	// PanelURL is the URL of the C2 panel's login page. It's stored, never fetched.
	PanelURL string `json:"panel_url"`
	// FirstSeen is the day ViriBack first saw the panel, at midnight UTC.
	FirstSeen time.Time `json:"first_seen"`
}

// Collect downloads the feed and returns one sighting per row. The feed is a CSV file whose
// columns are malware family, panel URL, IP address and first-seen date, after a header row.
// Malformed rows are skipped with a warning.
func (feed *Feed) Collect(ctx context.Context) ([]aggregator.Sighting, error) {
	body, err := feed.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    feed.url,
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("downloading feed: %w", err)
	}

	rows := aggregator.ReadCSVRows(ctx, feed.logger, SOURCE_NAME, body, COLUMN_COUNT)

	return aggregator.ConvertEntries(ctx, feed.logger, SOURCE_NAME, rows, newSighting), nil
}

// newSighting converts one row into a sighting. row has exactly COLUMN_COUNT columns.
func newSighting(row []string) (aggregator.Sighting, error) {
	family, panelURL, rawAddress, rawFirstSeen := row[0], row[1], row[2], row[3]

	address, err := aggregator.ParseAddress(rawAddress)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing row: %w", err)
	}

	firstSeen, err := time.ParseInLocation(DATE_LAYOUT, rawFirstSeen, time.UTC)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing first-seen date %q: %w", rawFirstSeen, err)
	}

	report := aggregator.NewReport(panelURL, []string{family}, Data{PanelURL: panelURL, FirstSeen: firstSeen})

	// A row without a malware family wouldn't say what the panel belongs to.
	if 0 == len(report.Flags) {
		return aggregator.Sighting{}, fmt.Errorf("row for %q has no malware family", address)
	}

	return aggregator.Sighting{Address: address, Report: report}, nil
}
