package extractors

import (
	"encoding/csv"
	"fmt"
	"strings"
)

// skipFirstLine returns body with its first line (the header row) removed.
func skipFirstLine(body string) string {
	i := strings.IndexAny(body, "\r\n")
	if -1 == i {
		return ""
	}

	// Treat \r\n as a single line break
	if '\r' == body[i] && i+1 < len(body) && '\n' == body[i+1] {
		i++
	}

	return body[i+1:]
}

// readCSVRows parses a CSV body, skipping its header row, and requires every
// record to have exactly fields columns.
func readCSVRows(body string, fields int) ([][]string, error) {
	reader := csv.NewReader(strings.NewReader(skipFirstLine(body)))
	reader.FieldsPerRecord = fields
	reader.LazyQuotes = true

	rows, err := reader.ReadAll()
	if nil != err {
		return nil, fmt.Errorf("parse csv: %w", err)
	}

	return rows, nil
}

// requireKeys returns an error naming the first key missing from obj.
func requireKeys(obj map[string]any, keys ...string) error {
	for _, key := range keys {
		if _, ok := obj[key]; false == ok {
			return fmt.Errorf("missing key %q", key)
		}
	}

	return nil
}

// stringField returns obj[key] as a string, or an error if it is not one.
func stringField(obj map[string]any, key string) (string, error) {
	s, ok := obj[key].(string)
	if false == ok {
		return "", fmt.Errorf("field %q is %T, want string", key, obj[key])
	}

	return s, nil
}

// getOr mirrors Python's dict.get(key, def): it returns def only when key is
// absent, so an explicit JSON null is passed through as nil.
func getOr(obj map[string]any, key string, def any) any {
	if v, ok := obj[key]; ok {
		return v
	}

	return def
}
