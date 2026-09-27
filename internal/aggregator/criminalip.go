package aggregator

import (
	"context"
	"io"
)

// Criminal IP's daily C2 feed.
const (
	// CRIMINALIP_SOURCE_NAME names the Criminal IP feed in sources.json and in published
	// results.
	CRIMINALIP_SOURCE_NAME = "criminalip"
	// CRIMINALIP_COLUMN_COUNT is the number of columns in each row: IP address, malware
	// family, port, score, country and scan time.
	CRIMINALIP_COLUMN_COUNT = 6
)

// criminalIPMetadata is the published metadata of a Criminal IP sighting. Every value is
// passed through from the feed as written.
//
// The struct tags set each field's JSON key. Keys and field order match the files published
// so far, so existing data and new data look the same.
type criminalIPMetadata struct {
	// Port is the open port Criminal IP found.
	Port string `json:"port"`
	// Score is Criminal IP's inbound and outbound risk score, such as "Critical/Critical".
	Score string `json:"score"`
	// Country is the address's two-letter country code.
	Country string `json:"country"`
	// ScanTime is when Criminal IP scanned the address, in the feed's own format.
	ScanTime string `json:"scanTime"`
}

// extractCriminalIP parses Criminal IP's daily C2 feed into one payload per row. The feed is a
// CSV file whose columns are IP address, malware family, port, score, country and scan time,
// after a header row. Malformed rows are skipped with a warning.
func (aggregator *Aggregator) extractCriminalIP(
	ctx context.Context,
	body io.Reader,
) ([]Payload, error) {
	rows, err := aggregator.readCSVRows(ctx, CRIMINALIP_SOURCE_NAME, body, CRIMINALIP_COLUMN_COUNT)
	if nil != err {
		return nil, err
	}

	// Every row records when this run collected the feed, not Criminal IP's scan time.
	ingestedAt := isoTime(aggregator.now().UTC())

	// The function literal is a closure: it uses ingestedAt from extractCriminalIP.
	convert := func(row []string) (Payload, error) {
		return newCriminalIPPayload(row, ingestedAt)
	}

	return convertEntries(ctx, aggregator.logger, CRIMINALIP_SOURCE_NAME, rows, convert), nil
}

// newCriminalIPPayload converts one Criminal IP row into a payload. row has exactly
// CRIMINALIP_COLUMN_COUNT columns.
func newCriminalIPPayload(row []string, ingestedAt isoTime) (Payload, error) {
	address, err := parseAddress(row[0])
	if nil != err {
		return Payload{}, err
	}

	metadata := criminalIPMetadata{
		Port:     row[2],
		Score:    row[3],
		Country:  row[4],
		ScanTime: row[5],
	}

	return newPayload(address, CRIMINALIP_SOURCE_NAME, row[1], ingestedAt, metadata)
}
