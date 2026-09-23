// Package payload defines the standard record shape shared by every
// aggregator extractor and the storage layer.
package payload

import "time"

// Result is a single sighting of an IP reported by one source.
type Result struct {
	Source   string         `json:"source"`
	Datetime string         `json:"datetime"`
	Flags    []string       `json:"flags"`
	Metadata map[string]any `json:"metadata"`
}

// Payload is everything known about a single IP address.
type Payload struct {
	IP      string   `json:"ip"`
	Flags   []string `json:"flags"`
	Results []Result `json:"results"`
}

// ISOFormat renders t the way Python's naive datetime.isoformat() does:
// microsecond precision, no timezone, and no fractional part when the
// microseconds are zero.
func ISOFormat(t time.Time) string {
	if 0 == t.Nanosecond()/1000 {
		return t.Format("2006-01-02T15:04:05")
	}

	return t.Format("2006-01-02T15:04:05.000000")
}

// Now returns the current local time formatted with ISOFormat. Extractors
// use it to record when the aggregator ingested an entry.
func Now() string {
	return ISOFormat(time.Now())
}
