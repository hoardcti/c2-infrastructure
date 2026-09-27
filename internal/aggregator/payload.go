package aggregator

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

// Layouts of the ISO 8601 timestamps this package publishes. They have no time zone because
// the published data has always been written that way; every value is in UTC.
const (
	// ISO_TIME_LAYOUT matches whole-second timestamps such as "2026-05-19T01:02:03".
	ISO_TIME_LAYOUT = "2006-01-02T15:04:05"
	// ISO_TIME_MICROSECONDS_LAYOUT matches timestamps with microseconds, such as
	// "2026-05-19T01:02:03.123456".
	ISO_TIME_MICROSECONDS_LAYOUT = "2006-01-02T15:04:05.000000"
)

// errUnsupportedEntry is returned by an entry converter for an upstream entry that is
// well-formed but doesn't describe an IP address, such as a ThreatFox domain indicator.
var errUnsupportedEntry = errors.New("entry doesn't describe an IP address")

// Payload is everything known about a single IP address. Each payload is published as one
// JSON file.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to name
// the field's JSON key.
type Payload struct {
	// IP is the address the payload describes. It's encoded as its text form, such as
	// "1.2.3.4".
	IP netip.Addr `json:"ip"`
	// Flags is the union of every result's flags.
	Flags []string `json:"flags"`
	// Results holds one sighting per source and set of flags.
	Results []Result `json:"results"`
}

// Result is a single sighting of an IP address reported by one source.
type Result struct {
	// Source names the feed that reported the address, as it's named in sources.json.
	Source string `json:"source"`
	// Datetime is when this program first collected the sighting.
	Datetime isoTime `json:"datetime"`
	// Flags are the lower-cased malware families the source reported.
	Flags []string `json:"flags"`
	// Metadata holds the source's own details about the sighting. It's kept as raw JSON
	// because every source publishes different fields: each extractor encodes it from its
	// own typed struct, and files read back from disk keep it exactly as it was written.
	Metadata jsontext.Value `json:"metadata"`
}

// isoTime is a moment written the way the published data has always written it: ISO 8601
// with no time zone, microsecond precision, and no fractional part when the microseconds are
// zero. This is the format of Python's datetime.isoformat(), which produced the first files.
type isoTime time.Time

// MarshalText formats the time for JSON output. encoding/json calls it to encode an isoTime
// as a JSON string. It uses a pointer receiver, like UnmarshalText, which must change the
// value it's called on; encoding/json/v2 calls it for values and pointers alike.
func (timestamp *isoTime) MarshalText() ([]byte, error) {
	moment := time.Time(*timestamp)
	if 0 == moment.Nanosecond()/int(time.Microsecond) {
		return moment.AppendFormat(nil, ISO_TIME_LAYOUT), nil
	}

	return moment.AppendFormat(nil, ISO_TIME_MICROSECONDS_LAYOUT), nil
}

// UnmarshalText parses a timestamp written by MarshalText, reading it as UTC.
func (timestamp *isoTime) UnmarshalText(text []byte) error {
	// When parsing, Go accepts an optional fractional second after the seconds even though the
	// layout doesn't show one, so this one layout reads both forms.
	moment, err := time.ParseInLocation(ISO_TIME_LAYOUT, string(text), time.UTC)
	if nil != err {
		return fmt.Errorf("parsing timestamp %q: %w", text, err)
	}

	*timestamp = isoTime(moment)

	return nil
}

// IsZero reports whether the timestamp was never set.
func (timestamp *isoTime) IsZero() bool {
	return time.Time(*timestamp).IsZero()
}

// parseAddress parses an IPv4 or IPv6 address taken from a feed. It refuses addresses that
// can't be stored (see isStorableAddress).
func parseAddress(rawAddress string) (netip.Addr, error) {
	address, err := netip.ParseAddr(rawAddress)
	if nil != err {
		return netip.Addr{}, fmt.Errorf("parsing IP address: %w", err)
	}

	if !isStorableAddress(address) {
		return netip.Addr{}, fmt.Errorf("refusing zoned IP address %q", rawAddress)
	}

	return address, nil
}

// isStorableAddress reports whether address can name a file. The zero netip.Addr isn't an
// address at all, and an IPv6 zone (the "eth0" in fe80::1%eth0) is free text chosen by
// whoever wrote the feed, so it can't safely become part of a file path.
func isStorableAddress(address netip.Addr) bool {
	return address.IsValid() && "" == address.Zone()
}

// newPayload builds the payload for one sighting of address by source. family is the malware
// family the source reported; it becomes the payload's only flag, lower-cased. metadata is the
// source's own typed details, encoded here so that every result stores raw JSON.
func newPayload(
	address netip.Addr,
	source string,
	family string,
	ingestedAt isoTime,
	metadata any,
) (Payload, error) {
	if "" == family {
		return Payload{}, errors.New("entry has no malware family")
	}

	// Keys are sorted in any maps inside the metadata so the published file doesn't change
	// between runs for the same data.
	encodedMetadata, err := json.Marshal(metadata, json.Deterministic(true))
	if nil != err {
		return Payload{}, fmt.Errorf("encoding metadata: %w", err)
	}

	flag := strings.ToLower(family)

	return Payload{
		IP:    address,
		Flags: []string{flag},
		Results: []Result{{
			Source:   source,
			Datetime: ingestedAt,
			Flags:    []string{flag},
			Metadata: encodedMetadata,
		}},
	}, nil
}

// convertEntries turns each upstream entry into a payload with convert. An entry that
// convert rejects is skipped with a warning, so one malformed entry doesn't stop the rest of
// the feed being published. Entries rejected with errUnsupportedEntry are expected and are
// only logged at debug level.
//
// [Entry any] is a type parameter: convertEntries works for any entry type, and the compiler
// works out Entry from the entries argument (CSV rows or raw JSON values).
func convertEntries[Entry any](
	ctx context.Context,
	logger *slog.Logger,
	sourceName string,
	entries []Entry,
	convert func(Entry) (Payload, error),
) []Payload {
	payloads := make([]Payload, 0, len(entries))

	for index, entry := range entries {
		payload, err := convert(entry)

		switch {
		case errors.Is(err, errUnsupportedEntry):
			logger.DebugContext(
				ctx,
				"skipping unsupported entry",
				"source", sourceName,
				"entry_index", index,
			)
		case nil != err:
			logger.WarnContext(
				ctx,
				"skipping malformed entry",
				"source", sourceName,
				"entry_index", index,
				"error", err,
			)
		default:
			payloads = append(payloads, payload)
		}
	}

	return payloads
}
