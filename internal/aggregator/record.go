package aggregator

import (
	"bytes"
	"cmp"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// SCHEMA_VERSION is the version of the record format this package writes. Version 1, the
// earlier {ip, flags, results} format, has no schema_version field; it's still read and
// converted (see decodeRecord).
const SCHEMA_VERSION = 2

// Layouts of the timestamps in version 1 records, which have no time zone and are in UTC.
const (
	// LEGACY_TIME_LAYOUT matches whole-second timestamps such as "2026-05-19T01:02:03". When
	// parsing, Go also accepts a fractional second after the seconds, so it reads timestamps
	// with microseconds too.
	LEGACY_TIME_LAYOUT = "2006-01-02T15:04:05"
)

// Record is everything known about one IP address: every observation every source has
// reported, with when it was reported. Observations are only ever added or extended, never
// replaced or removed, so the record is the address's complete history. Each record is
// published as one JSON file.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to name the
// field's JSON key, and omitzero leaves the field out when it holds its zero value.
type Record struct {
	// SchemaVersion is SCHEMA_VERSION, so consumers can tell formats apart.
	SchemaVersion int `json:"schema_version"`
	// IP is the address the record describes, encoded as its text form, such as "1.2.3.4".
	IP netip.Addr `json:"ip"`
	// FirstSeen is when a source first reported the address as a C2 server: the earliest
	// first_observed of an observation with flags. It's left out until one has.
	FirstSeen time.Time `json:"first_seen,omitzero"`
	// LastSeen is the latest last_observed of an observation with flags.
	LastSeen time.Time `json:"last_seen,omitzero"`
	// Flags is the sorted union of every observation's flags (lower-cased malware families).
	Flags []string `json:"flags"`
	// Sources holds each source's history, keyed by the source's name in sources.json.
	Sources map[string]SourceHistory `json:"sources"`
}

// SourceHistory is everything one source has reported about an address.
type SourceHistory struct {
	// LastChecked is when the source last answered for the address: when a feed last listed
	// it, or when an enricher last looked it up, whether or not it had anything to report.
	LastChecked time.Time `json:"last_checked,omitzero"`
	// LastError describes the most recent failed lookup since the last successful one. It's
	// cleared, and so left out, once a lookup succeeds.
	LastError SourceError `json:"last_error,omitzero"`
	// Observations holds every distinct report, oldest first.
	Observations []Observation `json:"observations"`
}

// SourceError records a failed lookup, so operators can see what went wrong for an address.
type SourceError struct {
	// OccurredAt is when the lookup failed.
	OccurredAt time.Time `json:"occurred_at"`
	// Message is the error. Errors never contain secrets (see Upstream).
	Message string `json:"message"`
}

// Observation is one report from a source, together with the period over which the source
// kept reporting exactly the same thing.
type Observation struct {
	// Key identifies what the observation is about within the source, such as a ThreatFox IOC
	// ID or a port, so changes to the same thing can be followed over time. It's empty, and
	// left out, for sources that report one thing per address.
	Key string `json:"key,omitzero"`
	// FirstObserved is when this program first collected the report.
	FirstObserved time.Time `json:"first_observed"`
	// LastObserved is when this program last collected exactly the same report.
	LastObserved time.Time `json:"last_observed"`
	// Flags are the lower-cased malware families in the report, if any.
	Flags []string `json:"flags,omitzero"`
	// Data is the source's own details, as a JSON object whose fields each source documents.
	Data jsontext.Value `json:"data"`
}

// Report is what a source says about an address in one run. The aggregator turns it into a
// new Observation, or extends an existing one with the same content. Build one with
// NewReport.
type Report struct {
	// Key identifies what the report is about within the source (see Observation.Key).
	Key string
	// Flags are the lower-cased, sorted, unique malware families.
	Flags []string
	// Data is the source's details as deterministic JSON.
	Data jsontext.Value
}

// NewReport builds a report from a source's typed details. Flags are lower-cased, sorted and
// deduplicated, and empty flags are dropped. data is encoded with sorted map keys, so the same
// details always give the same JSON, and invalid UTF-8 from upstream text is replaced rather
// than refused.
//
// data must be a value encoding/json can encode, such as a struct of strings, numbers, times
// and slices. Anything else is a programming mistake in the source, so NewReport panics.
func NewReport(key string, flags []string, data any) Report {
	encodedData, err := json.Marshal(data, json.Deterministic(true), jsontext.AllowInvalidUTF8(true))
	if nil != err {
		panic(fmt.Sprintf("encoding report data of type %T: %v", data, err))
	}

	return Report{Key: key, Flags: normaliseFlags(flags), Data: encodedData}
}

// normaliseFlags returns flags lower-cased, sorted and without duplicates or empty values.
func normaliseFlags(flags []string) []string {
	var normalised []string

	for _, flag := range flags {
		if "" != flag {
			normalised = append(normalised, strings.ToLower(flag))
		}
	}

	return SortedUnique(normalised)
}

// SortedUnique returns a sorted copy of values without duplicates, or nil when values is
// empty. Sources use it for lists whose upstream order means nothing, so a reordered list
// isn't stored as a change. Returning nil for an empty list means an upstream's [] and null
// encode the same way.
//
// [Value cmp.Ordered] is a type parameter: SortedUnique works for any type that can be
// compared with <, such as strings and integers.
func SortedUnique[Value cmp.Ordered](values []Value) []Value {
	if 0 == len(values) {
		return nil
	}

	// Clone copies the elements, so sorting never changes the caller's slice: slices share
	// their underlying array when assigned.
	sorted := slices.Clone(values)
	slices.Sort(sorted)

	return slices.Compact(sorted)
}

// newRecord returns an empty record for address.
func newRecord(address netip.Addr) Record {
	return Record{
		SchemaVersion: SCHEMA_VERSION,
		IP:            address,
		Flags:         []string{},
		Sources:       map[string]SourceHistory{},
	}
}

// addReports records that sourceName reported reports for the record's address at checkedAt.
//
// A report identical to the latest observation with the same key (same flags, and data equal
// as canonical JSON) only moves that observation's last_observed forward. Any other report is
// appended as a new observation, so earlier values stay in the history. A source's error is
// cleared, because it has answered.
func (record *Record) addReports(sourceName string, reports []Report, checkedAt time.Time) {
	// A missing map entry reads as the zero value: a history with no observations. The history
	// is a copy, so it's written back below.
	history := record.Sources[sourceName]
	history.LastChecked = checkedAt
	history.LastError = SourceError{}

	for _, report := range reports {
		latestIndex := latestObservationIndex(history.Observations, report.Key)

		isUnchanged := -1 != latestIndex && hasSameContent(history.Observations[latestIndex], report)
		if isUnchanged {
			latest := &history.Observations[latestIndex]
			if checkedAt.After(latest.LastObserved) {
				latest.LastObserved = checkedAt
			}

			continue
		}

		history.Observations = append(history.Observations, Observation{
			Key:           report.Key,
			FirstObserved: checkedAt,
			LastObserved:  checkedAt,
			Flags:         report.Flags,
			Data:          report.Data,
		})
	}

	// Go has no "nil-safe" maps: a nil map can be read but not written. Records from newRecord
	// and decodeRecord always have one, but a hand-built Record might not.
	if nil == record.Sources {
		record.Sources = map[string]SourceHistory{}
	}

	record.Sources[sourceName] = history
	record.summarise()
}

// latestObservationIndex returns the index of the newest observation with key, or -1 if there
// is none.
func latestObservationIndex(observations []Observation, key string) int {
	for index, observation := range slices.Backward(observations) {
		if key == observation.Key {
			return index
		}
	}

	return -1
}

// hasSameContent reports whether report says exactly what observation says. Data is compared
// by meaning, so a different key order or spacing still counts as the same. Data that isn't
// valid JSON never counts as the same.
func hasSameContent(observation Observation, report Report) bool {
	if !slices.Equal(observation.Flags, report.Flags) {
		return false
	}

	// Canonicalize rewrites a value in place into RFC 8785 form (sorted keys, normalised
	// numbers), so it runs on copies.
	observedData := observation.Data.Clone()
	reportedData := report.Data.Clone()
	canonicalizeErr := errors.Join(observedData.Canonicalize(), reportedData.Canonicalize())

	return nil == canonicalizeErr && bytes.Equal(observedData, reportedData)
}

// recordFailure records that sourceName failed to look the record's address up at
// occurredAt. Observations and last_checked are left as they were.
func (record *Record) recordFailure(sourceName, message string, occurredAt time.Time) {
	history := record.Sources[sourceName]
	history.LastError = SourceError{OccurredAt: occurredAt, Message: message}

	if nil == record.Sources {
		record.Sources = map[string]SourceHistory{}
	}

	record.Sources[sourceName] = history
}

// summarise recomputes the record's flags, first_seen and last_seen from its observations.
// Only observations with flags count towards first_seen and last_seen: they're the ones that
// report the address as a C2 server, while enrichment without flags only describes it.
func (record *Record) summarise() {
	flags := []string{}
	record.FirstSeen = time.Time{}
	record.LastSeen = time.Time{}

	for _, history := range record.Sources {
		for _, observation := range history.Observations {
			if 0 == len(observation.Flags) {
				continue
			}

			flags = append(flags, observation.Flags...)

			if record.FirstSeen.IsZero() || observation.FirstObserved.Before(record.FirstSeen) {
				record.FirstSeen = observation.FirstObserved
			}

			if observation.LastObserved.After(record.LastSeen) {
				record.LastSeen = observation.LastObserved
			}
		}
	}

	// Map iteration order is random in Go, so the flags are sorted to make the output stable.
	slices.Sort(flags)
	record.Flags = slices.Compact(flags)
}

// lastAttempt returns when sourceName last tried to look the address up, successfully or
// not, and false if it never has.
func (record *Record) lastAttempt(sourceName string) (time.Time, bool) {
	// The comma-ok form: ok is false when the map has no entry for the name.
	history, ok := record.Sources[sourceName]
	if !ok {
		return time.Time{}, false
	}

	if history.LastError.OccurredAt.After(history.LastChecked) {
		return history.LastError.OccurredAt, true
	}

	return history.LastChecked, true
}

// decodeRecord decodes a stored file. A version 1 file is converted into a record (see
// migrateLegacyPayload); any other version than SCHEMA_VERSION is refused.
func decodeRecord(content []byte) (Record, error) {
	// Only the version is read first; the other fields are ignored by this decode.
	var header struct {
		// SchemaVersion is 0 when the field is missing, as in version 1 files.
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(content, &header); nil != err {
		return Record{}, fmt.Errorf("decoding record: %w", err)
	}

	switch header.SchemaVersion {
	case 0:
		var legacy legacyPayload
		if err := json.Unmarshal(content, &legacy); nil != err {
			return Record{}, fmt.Errorf("decoding version 1 record: %w", err)
		}

		return migrateLegacyPayload(legacy), nil
	case SCHEMA_VERSION:
		var record Record
		if err := json.Unmarshal(content, &record); nil != err {
			return Record{}, fmt.Errorf("decoding record: %w", err)
		}

		// Files written by hand or by an older build may lack the collections.
		if nil == record.Sources {
			record.Sources = map[string]SourceHistory{}
		}

		return record, nil
	}

	return Record{}, fmt.Errorf("unsupported schema version %d", header.SchemaVersion)
}

// legacyPayload is a version 1 record: the union of flags and one result per source and set
// of flags, whose metadata was replaced whenever the source reported it again.
type legacyPayload struct {
	// IP is the address the payload describes.
	IP netip.Addr `json:"ip"`
	// Results holds one sighting per source and set of flags.
	Results []legacyResult `json:"results"`
}

// legacyResult is one sighting in a version 1 record.
type legacyResult struct {
	// Source names the feed that reported the address.
	Source string `json:"source"`
	// Datetime is when the sighting was first collected.
	Datetime legacyTime `json:"datetime"`
	// Flags are the lower-cased malware families.
	Flags []string `json:"flags"`
	// Metadata holds the source's details, in the version 1 field names.
	Metadata jsontext.Value `json:"metadata"`
}

// migrateLegacyPayload converts a version 1 record into a record without losing anything:
// every result becomes an observation, keeping its metadata exactly as it was. Version 1 kept
// only the time a result was first collected, so that is both its first and last observation.
// Migrated observations have no key, because version 1 didn't record one; the next report
// from the same source starts a new, keyed observation next to them.
func migrateLegacyPayload(legacy legacyPayload) Record {
	record := newRecord(legacy.IP)

	for _, result := range legacy.Results {
		collectedAt := time.Time(result.Datetime)
		history := record.Sources[result.Source]

		history.Observations = append(history.Observations, Observation{
			FirstObserved: collectedAt,
			LastObserved:  collectedAt,
			Flags:         normaliseFlags(result.Flags),
			Data:          result.Metadata,
		})

		if collectedAt.After(history.LastChecked) {
			history.LastChecked = collectedAt
		}

		record.Sources[result.Source] = history
	}

	record.summarise()

	return record
}

// legacyTime is a version 1 timestamp: ISO 8601 with no time zone, in UTC, with or without
// microseconds.
type legacyTime time.Time

// UnmarshalText parses a version 1 timestamp. encoding/json calls it to decode a legacyTime
// from a JSON string; it needs a pointer receiver because it changes the value it's called on.
func (timestamp *legacyTime) UnmarshalText(text []byte) error {
	moment, err := time.ParseInLocation(LEGACY_TIME_LAYOUT, string(text), time.UTC)
	if nil != err {
		return fmt.Errorf("parsing timestamp %q: %w", text, err)
	}

	*timestamp = legacyTime(moment)

	return nil
}
