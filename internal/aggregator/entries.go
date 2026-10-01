package aggregator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

// ErrUnsupportedEntry is returned by an entry converter for an upstream entry that is
// well-formed but doesn't describe an IP address, such as a ThreatFox domain indicator.
// ConvertEntries skips such entries quietly.
var ErrUnsupportedEntry = errors.New("entry doesn't describe an IP address")

// ParseAddress parses an IPv4 or IPv6 address taken from upstream data. It refuses addresses
// that can't be stored: zoned IPv6 addresses and IPv4-mapped IPv6 addresses.
func ParseAddress(rawAddress string) (netip.Addr, error) {
	address, err := netip.ParseAddr(rawAddress)
	if nil != err {
		return netip.Addr{}, fmt.Errorf("parsing IP address: %w", err)
	}

	if !isStorableAddress(address) {
		return netip.Addr{}, fmt.Errorf("refusing IP address %q", rawAddress)
	}

	return address, nil
}

// ConvertEntries turns each upstream entry of a feed into a sighting with convert. An entry
// that convert rejects is skipped with a warning, so one malformed entry doesn't stop the rest
// of the feed being stored. Entries rejected with ErrUnsupportedEntry are expected and only
// logged at debug level.
//
// [Entry any] is a type parameter: ConvertEntries works for any entry type, and the compiler
// works out Entry from the entries argument (CSV rows or raw JSON values).
func ConvertEntries[Entry any](
	ctx context.Context,
	logger *slog.Logger,
	sourceName string,
	entries []Entry,
	convert func(Entry) (Sighting, error),
) []Sighting {
	sightings := make([]Sighting, 0, len(entries))

	for index, entry := range entries {
		sighting, err := convert(entry)

		switch {
		case errors.Is(err, ErrUnsupportedEntry):
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
			sightings = append(sightings, sighting)
		}
	}

	return sightings
}
