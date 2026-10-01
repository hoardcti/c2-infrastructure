// Package feodotracker is the Feodo Tracker feed: abuse.ch's blocklist of botnet C2 servers.
//
// Each blocklist entry becomes an observation keyed by the C2 server's port, so a change of
// status (online or offline) or hosting shows up as a new observation. The blocklist needs no
// key and is published under CC0.
//
// It's a package of its own, imported only by the command, because it hides the blocklist's
// upstream types from the rest of the program (GO-PKG-004, reason 3), like every source.
package feodotracker

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The Feodo Tracker blocklist.
const (
	// SOURCE_NAME names Feodo Tracker in sources.json and in every record.
	SOURCE_NAME = "feodotracker"
	// MAX_RESPONSE_BYTES bounds the blocklist, which has never been more than a few MiB.
	MAX_RESPONSE_BYTES = 64 << 20
	// FIRST_SEEN_LAYOUT matches the blocklist's first_seen, such as "2025-12-30 13:56:31", in
	// UTC.
	FIRST_SEEN_LAYOUT = "2006-01-02 15:04:05"
	// LAST_ONLINE_LAYOUT matches the blocklist's last_online, such as "2026-03-12".
	LAST_ONLINE_LAYOUT = "2006-01-02"
)

// Feed downloads the Feodo Tracker blocklist. Build one with New.
type Feed struct {
	// url is the blocklist's JSON download.
	url string
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// logger receives skipped-entry messages.
	logger *slog.Logger
}

// New builds the Feodo Tracker feed from its sources.json entry.
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

// entry mirrors one entry of the JSON blocklist. Upstream fields that aren't stored are left
// out, and encoding/json ignores them when decoding.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type entry struct {
	// IPAddress is the C2 server's address.
	IPAddress string `json:"ip_address"`
	// Port is the port the C2 server listens on.
	Port uint16 `json:"port"`
	// Status is "online" or "offline".
	Status string `json:"status"`
	// Hostname is the server's reverse DNS name, or nil when the upstream sends null.
	Hostname *string `json:"hostname"`
	// ASNumber is the autonomous system the address belongs to.
	ASNumber int `json:"as_number"`
	// ASName is the autonomous system's name.
	ASName string `json:"as_name"`
	// Country is the address's two-letter country code.
	Country string `json:"country"`
	// FirstSeen is when Feodo Tracker first saw the server, in FIRST_SEEN_LAYOUT.
	FirstSeen string `json:"first_seen"`
	// LastOnline is the day the server was last seen online, in LAST_ONLINE_LAYOUT, or null.
	LastOnline *string `json:"last_online"`
	// Malware is the malware family, such as "QakBot".
	Malware string `json:"malware"`
}

// Data is what a Feodo Tracker observation stores about one C2 server.
type Data struct {
	// Port is the port the C2 server listens on.
	Port uint16 `json:"port"`
	// Status is "online" or "offline".
	Status string `json:"status"`
	// Hostname is the server's reverse DNS name, or nil (stored as null) when unknown.
	Hostname *string `json:"hostname"`
	// ASNumber is the autonomous system the address belongs to.
	ASNumber int `json:"as_number"`
	// ASName is the autonomous system's name.
	ASName string `json:"as_name"`
	// Country is the address's two-letter country code.
	Country string `json:"country"`
	// FirstSeen is when Feodo Tracker first saw the server.
	FirstSeen time.Time `json:"first_seen"`
	// LastOnline is the day the server was last seen online, at midnight UTC, or nil (stored as
	// null) when unknown.
	LastOnline *time.Time `json:"last_online"`
}

// Collect downloads the blocklist and returns one sighting per entry. Malformed entries are
// skipped with a warning.
func (feed *Feed) Collect(ctx context.Context) ([]aggregator.Sighting, error) {
	body, err := feed.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    feed.url,
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("downloading blocklist: %w", err)
	}

	// Each entry is kept as raw JSON and decoded on its own below, so a malformed entry is
	// skipped instead of failing the whole blocklist.
	var entries []jsontext.Value
	if err := json.Unmarshal(body, &entries); nil != err {
		return nil, fmt.Errorf("decoding blocklist: %w", err)
	}

	return aggregator.ConvertEntries(ctx, feed.logger, SOURCE_NAME, entries, newSighting), nil
}

// newSighting converts one raw blocklist entry into a sighting.
func newSighting(rawEntry jsontext.Value) (aggregator.Sighting, error) {
	var decoded entry
	if err := json.Unmarshal(rawEntry, &decoded); nil != err {
		return aggregator.Sighting{}, fmt.Errorf("decoding entry: %w", err)
	}

	address, err := aggregator.ParseAddress(decoded.IPAddress)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing entry: %w", err)
	}

	firstSeen, err := time.ParseInLocation(FIRST_SEEN_LAYOUT, decoded.FirstSeen, time.UTC)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing first_seen %q: %w", decoded.FirstSeen, err)
	}

	// A pointer is nil when the value is absent; new(value) returns a pointer to a copy.
	var lastOnline *time.Time

	if nil != decoded.LastOnline {
		day, err := time.ParseInLocation(LAST_ONLINE_LAYOUT, *decoded.LastOnline, time.UTC)
		if nil != err {
			return aggregator.Sighting{}, fmt.Errorf("parsing last_online %q: %w", *decoded.LastOnline, err)
		}

		lastOnline = new(day)
	}

	report := aggregator.NewReport(strconv.Itoa(int(decoded.Port)), []string{decoded.Malware}, Data{
		Port:       decoded.Port,
		Status:     decoded.Status,
		Hostname:   decoded.Hostname,
		ASNumber:   decoded.ASNumber,
		ASName:     decoded.ASName,
		Country:    decoded.Country,
		FirstSeen:  firstSeen,
		LastOnline: lastOnline,
	})

	// An entry without a malware family wouldn't say what the C2 server belongs to.
	if 0 == len(report.Flags) {
		return aggregator.Sighting{}, fmt.Errorf("entry for %q has no malware family", address)
	}

	return aggregator.Sighting{Address: address, Report: report}, nil
}
