package aggregator

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"log/slog"
)

// ReadCSVRows reads a downloaded CSV feed and returns its rows without the header row. Rows
// that don't have exactly columnCount columns are skipped with a warning to logger, so one
// malformed row doesn't stop the rest of the feed being stored.
func ReadCSVRows(
	ctx context.Context,
	logger *slog.Logger,
	sourceName string,
	body []byte,
	columnCount int,
) [][]string {
	reader := csv.NewReader(bytes.NewReader(body))
	// Column counts are checked row by row below instead of by the reader, so that a malformed
	// row is skipped rather than failing the whole feed, and the header may differ.
	reader.FieldsPerRecord = -1
	// Feeds sometimes contain stray quotes inside unquoted fields; read them as literal text.
	reader.LazyQuotes = true

	var rows [][]string

	// The first record is the header row, so row numbers in warnings count it as row 1. The
	// loop ends when the reader reaches the end of body.
	for rowNumber := 1; ; rowNumber++ {
		record, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return rows
		}

		// With LazyQuotes and no fixed column count, reading fails only when the underlying
		// reader does, and body is already in memory.
		if nil != err { // coverage-ignore -- reading from memory never fails.
			logger.WarnContext(ctx, "skipping unreadable CSV feed", "source", sourceName, "error", err)

			return rows
		}

		isMalformed := columnCount != len(record)

		switch {
		case 1 == rowNumber:
			// The header's own column count doesn't matter.
		case isMalformed:
			logger.WarnContext(
				ctx,
				"skipping malformed CSV row",
				"source", sourceName,
				"row_number", rowNumber,
				"column_count", len(record),
			)
		default:
			rows = append(rows, record)
		}
	}
}
