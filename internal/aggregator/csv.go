package aggregator

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
)

// readCSVRows reads a CSV feed body and returns its rows without the header row. Rows that
// don't have exactly columnCount columns are skipped with a warning, so one malformed row
// doesn't stop the rest of the feed being published.
func (aggregator *Aggregator) readCSVRows(
	ctx context.Context,
	sourceName string,
	body io.Reader,
	columnCount int,
) ([][]string, error) {
	reader := csv.NewReader(body)
	// Column counts are checked row by row below instead of by the reader, so that a malformed
	// row is skipped rather than failing the whole feed, and the header may differ.
	reader.FieldsPerRecord = -1
	// Feeds sometimes contain stray quotes inside unquoted fields; read them as literal text.
	reader.LazyQuotes = true

	// With LazyQuotes and no fixed column count, reading fails only when body itself does.
	records, err := reader.ReadAll()
	if nil != err {
		return nil, fmt.Errorf("reading CSV: %w", err)
	}

	if 0 == len(records) {
		return nil, nil
	}

	// The first record is the header row. Row numbers in warnings count it as row 1.
	rows := make([][]string, 0, len(records)-1)

	for index, record := range records[1:] {
		if columnCount != len(record) {
			aggregator.logger.WarnContext(
				ctx,
				"skipping malformed CSV row",
				"source", sourceName,
				"row_number", index+2,
				"column_count", len(record),
			)

			continue
		}

		rows = append(rows, record)
	}

	return rows, nil
}
