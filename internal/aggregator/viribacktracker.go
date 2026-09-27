package aggregator

import (
	"context"
	"fmt"
	"io"
	"time"
)

// The ViriBack C2 tracker feed.
const (
	// VIRIBACKTRACKER_SOURCE_NAME names the ViriBack feed in sources.json and in published
	// results.
	VIRIBACKTRACKER_SOURCE_NAME = "viribacktracker"
	// VIRIBACKTRACKER_COLUMN_COUNT is the number of columns in each row: malware family, panel
	// URL, IP address and first-seen date.
	VIRIBACKTRACKER_COLUMN_COUNT = 4
	// VIRIBACK_DATE_LAYOUT matches ViriBack's day-month-year dates, such as "26-09-2026" or
	// "7-3-2026": the day and month may be unpadded.
	VIRIBACK_DATE_LAYOUT = "2-1-2006"
)

// viriBackTrackerMetadata is the published metadata of a ViriBack sighting.
//
// The struct tags set each field's JSON key. Keys and field order match the files published
// so far, so existing data and new data look the same.
type viriBackTrackerMetadata struct {
	// FirstSeen is the day ViriBack first saw the C2 panel, at midnight UTC.
	FirstSeen isoTime `json:"firstSeen"`
	// Login is the URL of the C2 panel's login page. It's published, never fetched.
	Login string `json:"login"`
}

// extractViriBackTracker parses the ViriBack C2 tracker feed into one payload per row. The feed
// is a CSV file whose columns are malware family, panel URL, IP address and first-seen date,
// after a header row. Malformed rows are skipped with a warning.
func (aggregator *Aggregator) extractViriBackTracker(
	ctx context.Context,
	body io.Reader,
) ([]Payload, error) {
	rows, err := aggregator.readCSVRows(
		ctx,
		VIRIBACKTRACKER_SOURCE_NAME,
		body,
		VIRIBACKTRACKER_COLUMN_COUNT,
	)
	if nil != err {
		return nil, err
	}

	// Every row records when this run collected the feed.
	ingestedAt := isoTime(aggregator.now().UTC())

	// The function literal is a closure: it uses ingestedAt from extractViriBackTracker.
	convert := func(row []string) (Payload, error) {
		return newViriBackTrackerPayload(row, ingestedAt)
	}

	return convertEntries(ctx, aggregator.logger, VIRIBACKTRACKER_SOURCE_NAME, rows, convert), nil
}

// newViriBackTrackerPayload converts one ViriBack row into a payload. row has exactly
// VIRIBACKTRACKER_COLUMN_COUNT columns.
func newViriBackTrackerPayload(row []string, ingestedAt isoTime) (Payload, error) {
	address, err := parseAddress(row[2])
	if nil != err {
		return Payload{}, err
	}

	firstSeen, err := time.ParseInLocation(VIRIBACK_DATE_LAYOUT, row[3], time.UTC)
	if nil != err {
		return Payload{}, fmt.Errorf("parsing first-seen date %q: %w", row[3], err)
	}

	metadata := viriBackTrackerMetadata{
		FirstSeen: isoTime(firstSeen),
		Login:     row[1],
	}

	return newPayload(address, VIRIBACKTRACKER_SOURCE_NAME, row[0], ingestedAt, metadata)
}
