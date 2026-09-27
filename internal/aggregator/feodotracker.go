package aggregator

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
)

// FEODOTRACKER_SOURCE_NAME names the Feodo Tracker blocklist in sources.json and in published
// results.
const FEODOTRACKER_SOURCE_NAME = "feodotracker"

// feodoTrackerEntry mirrors one entry of Feodo Tracker's JSON blocklist. Upstream fields that
// aren't published are left out, and encoding/json ignores them when decoding.
//
// The struct tags set the upstream JSON key each field is read from.
type feodoTrackerEntry struct {
	// IPAddress is the C2 server's address.
	IPAddress string `json:"ip_address"`
	// Port is the port the C2 server listens on.
	Port int `json:"port"`
	// Hostname is the server's reverse DNS name. It's nil when the upstream sends null, which
	// is published as null rather than as an empty string.
	Hostname *string `json:"hostname"`
	// Country is the address's two-letter country code.
	Country string `json:"country"`
	// FirstSeen is when Feodo Tracker first saw the server, in the upstream's own format.
	FirstSeen string `json:"first_seen"`
	// LastOnline is the day the server was last seen online, in the upstream's own format.
	LastOnline string `json:"last_online"`
	// Malware is the malware family, such as "QakBot".
	Malware string `json:"malware"`
}

// feodoTrackerMetadata is the published metadata of a Feodo Tracker sighting. Its values are
// passed through from the upstream entry.
//
// Keys and field order match the files published so far, so existing data and new data look
// the same.
type feodoTrackerMetadata struct {
	// Country is the address's two-letter country code.
	Country string `json:"country"`
	// FirstSeen is when Feodo Tracker first saw the server.
	FirstSeen string `json:"firstSeen"`
	// LastOnline is the day the server was last seen online.
	LastOnline string `json:"lastOnline"`
	// Hostname is the server's reverse DNS name, or nil (published as null) when unknown.
	Hostname *string `json:"hostname"`
	// Port is the port the C2 server listens on.
	Port int `json:"port"`
}

// extractFeodoTracker parses Feodo Tracker's JSON blocklist into one payload per entry.
// Malformed entries are skipped with a warning.
func (aggregator *Aggregator) extractFeodoTracker(
	ctx context.Context,
	body io.Reader,
) ([]Payload, error) {
	// Each entry is kept as raw JSON and decoded on its own below, so a malformed entry is
	// skipped instead of failing the whole blocklist.
	var entries []jsontext.Value
	if err := json.UnmarshalRead(body, &entries); nil != err {
		return nil, fmt.Errorf("decoding blocklist: %w", err)
	}

	// Every entry records when this run collected the blocklist.
	ingestedAt := isoTime(aggregator.now().UTC())

	// The function literal is a closure: it uses ingestedAt from extractFeodoTracker.
	convert := func(rawEntry jsontext.Value) (Payload, error) {
		return newFeodoTrackerPayload(rawEntry, ingestedAt)
	}

	return convertEntries(ctx, aggregator.logger, FEODOTRACKER_SOURCE_NAME, entries, convert), nil
}

// newFeodoTrackerPayload converts one raw blocklist entry into a payload.
func newFeodoTrackerPayload(rawEntry jsontext.Value, ingestedAt isoTime) (Payload, error) {
	var entry feodoTrackerEntry
	if err := json.Unmarshal(rawEntry, &entry); nil != err {
		return Payload{}, fmt.Errorf("decoding entry: %w", err)
	}

	address, err := parseAddress(entry.IPAddress)
	if nil != err {
		return Payload{}, err
	}

	metadata := feodoTrackerMetadata{
		Country:    entry.Country,
		FirstSeen:  entry.FirstSeen,
		LastOnline: entry.LastOnline,
		Hostname:   entry.Hostname,
		Port:       entry.Port,
	}

	return newPayload(address, FEODOTRACKER_SOURCE_NAME, entry.Malware, ingestedAt, metadata)
}
