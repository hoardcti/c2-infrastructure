// Package threatfox is the ThreatFox feed: C2 indicators from abuse.ch's ThreatFox API.
//
// ThreatFox reports indicators of compromise with their malware family. This feed queries it
// with the query in sources.json (by default every indicator tagged "c2" in the last day) and
// keeps the ip:port indicators. Each indicator becomes an observation keyed by its ThreatFox
// ID, so a change to the same indicator, such as a corrected family, shows up as a new
// observation next to the old one.
//
// It's a package of its own, imported only by the command, because it hides state the rest
// of the program mustn't touch: the abuse.ch Auth-Key and ThreatFox's response types
// (GO-PKG-004, reason 3). Every source follows the same layout, so adding one never means
// editing another.
package threatfox

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The ThreatFox API.
const (
	// SOURCE_NAME names ThreatFox in sources.json and in every record.
	SOURCE_NAME = "threatfox"
	// MAX_RESPONSE_BYTES bounds a ThreatFox response. A query returns at most 1,000
	// indicators, about 1 MiB.
	MAX_RESPONSE_BYTES = 32 << 20
	// TIME_LAYOUT matches ThreatFox timestamps, such as "2026-05-19 10:11:12 UTC".
	TIME_LAYOUT = "2006-01-02 15:04:05 MST"
	// OK_STATUS is the query_status of a successful query with results.
	OK_STATUS = "ok"
	// NO_RESULT_STATUS is the query_status of a successful query without results.
	NO_RESULT_STATUS = "no_result"
	// IP_PORT_TYPE is the ioc_type of an "address:port" indicator, the only kind that describes
	// an IP address.
	IP_PORT_TYPE = "ip:port"
	// UNKNOWN_MALWARE is the flag recorded when ThreatFox gives no malware family.
	UNKNOWN_MALWARE = "unknown"
)

// Query is the JSON request body sent to ThreatFox, set by the source's options in
// sources.json.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to name the
// field's JSON key, and omitzero leaves the field out of the request when it's empty.
type Query struct {
	// Query is the API operation, such as "taginfo"; required.
	Query string `json:"query"`
	// Tag selects indicators with this tag.
	Tag string `json:"tag,omitzero"`
	// Days limits results to indicators first seen in this many days.
	Days int `json:"days,omitzero"`
	// Limit is the maximum number of indicators returned; at least 1.
	Limit int `json:"limit"`
}

// Feed queries ThreatFox. Build one with New.
type Feed struct {
	// url is the ThreatFox API endpoint.
	url string
	// requestBody is the Query as JSON.
	requestBody []byte
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// apiKey is the abuse.ch Auth-Key.
	apiKey aggregator.APIKey
	// logger receives skipped-indicator messages.
	logger *slog.Logger
}

// New builds the ThreatFox feed from its sources.json entry. The entry's options must be a
// Query with a query and a limit of at least 1, and apiKey must be set.
func New(
	config aggregator.SourceConfig,
	upstream *aggregator.Upstream,
	apiKey aggregator.APIKey,
	logger *slog.Logger,
) (*Feed, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	var query Query
	if err = aggregator.DecodeOptions(config.Options, &query); nil != err {
		return nil, fmt.Errorf("checking options: %w", err)
	}

	if "" == query.Query || query.Limit < 1 {
		return nil, errors.New("options need a query and a limit of at least 1")
	}

	// ThreatFox rejects requests without an Auth-Key, so fail now rather than on every run.
	if "" == apiKey {
		return nil, errors.New("the abuse.ch Auth-Key is required")
	}

	// The request body is the options exactly as written in sources.json: DecodeOptions has
	// just checked that they hold only Query's fields. Clone copies them, so the feed never
	// shares memory with the configuration.
	return &Feed{
		url:         endpoint.String(),
		requestBody: slices.Clone(config.Options),
		upstream:    upstream,
		apiKey:      apiKey,
		logger:      logger,
	}, nil
}

// response mirrors a ThreatFox API response. The struct tags set the upstream JSON key each
// field is read from.
type response struct {
	// QueryStatus is "ok" on success, or a code such as "unknown_auth_key".
	QueryStatus string `json:"query_status"`
	// Data holds the indicators when QueryStatus is "ok", or a message otherwise. Each
	// indicator is kept as raw JSON and decoded on its own, so a malformed one is skipped
	// instead of failing the query.
	Data jsontext.Value `json:"data"`
}

// indicator mirrors one indicator in a ThreatFox response. Upstream fields that aren't stored
// are left out, and encoding/json ignores them when decoding.
type indicator struct {
	// ID is ThreatFox's identifier for the indicator.
	ID string `json:"id"`
	// IOC is the indicator itself; for an ip:port indicator, such as "1.2.3.4:443".
	IOC string `json:"ioc"`
	// IOCType is the kind of indicator, such as "ip:port" or "domain".
	IOCType string `json:"ioc_type"`
	// ThreatType is the kind of threat, such as "botnet_cc".
	ThreatType string `json:"threat_type"`
	// MalwarePrintable is the malware family's display name, such as "Cobalt Strike".
	MalwarePrintable string `json:"malware_printable"`
	// MalwareMalpedia is the family's Malpedia page. It's stored, never fetched.
	MalwareMalpedia string `json:"malware_malpedia"`
	// ConfidenceLevel is ThreatFox's confidence in the indicator, from 0 to 100.
	ConfidenceLevel int `json:"confidence_level"`
	// FirstSeen is when ThreatFox first saw the indicator, in TIME_LAYOUT.
	FirstSeen string `json:"first_seen"`
	// Reference is a URL the reporter cited, or nil when the upstream sends null. It's stored,
	// never fetched.
	Reference *string `json:"reference"`
	// Tags are the reporter's tags, such as "c2".
	Tags []string `json:"tags"`
}

// Data is what a ThreatFox observation stores about one indicator.
type Data struct {
	// IOC is the whole indicator, such as "1.2.3.4:443".
	IOC string `json:"ioc"`
	// Port is the port part of the indicator.
	Port uint16 `json:"port"`
	// ThreatType is the kind of threat, such as "botnet_cc".
	ThreatType string `json:"threat_type"`
	// Malware is the malware family's display name, such as "Cobalt Strike".
	Malware string `json:"malware"`
	// MalwareMalpedia is the malware family's Malpedia page.
	MalwareMalpedia string `json:"malware_malpedia"`
	// ConfidenceLevel is ThreatFox's confidence in the indicator, from 0 to 100.
	ConfidenceLevel int `json:"confidence_level"`
	// FirstSeen is when ThreatFox first saw the indicator.
	FirstSeen time.Time `json:"first_seen"`
	// Reference is a URL the reporter cited, or nil (stored as null).
	Reference *string `json:"reference"`
	// Tags are the reporter's tags, sorted.
	Tags []string `json:"tags"`
}

// Collect queries ThreatFox and returns a sighting for every ip:port indicator in the
// response. Other indicators are skipped, and malformed ones are skipped with a warning.
func (feed *Feed) Collect(ctx context.Context) ([]aggregator.Sighting, error) {
	// The key goes in a header, never in the URL, so it can't leak through URLs in logs or
	// errors.
	header := http.Header{}
	header.Set("Accept", "application/json")
	header.Set("Content-Type", "application/json")
	header.Set("Auth-Key", string(feed.apiKey))

	responseBody, err := feed.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodPost,
		URL:    feed.url,
		Header: header,
		Body:   feed.requestBody,
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("querying ThreatFox: %w", err)
	}

	return feed.convertResponse(ctx, responseBody)
}

// convertResponse returns a sighting for every ip:port indicator in a ThreatFox response
// body. It fails if the query itself failed.
func (feed *Feed) convertResponse(ctx context.Context, responseBody []byte) ([]aggregator.Sighting, error) {
	var decoded response
	if err := json.Unmarshal(responseBody, &decoded); nil != err {
		return nil, fmt.Errorf("decoding ThreatFox response: %w", err)
	}

	switch decoded.QueryStatus {
	case NO_RESULT_STATUS:
		return nil, nil
	case OK_STATUS:
	default:
		return nil, fmt.Errorf("ThreatFox query failed with status %q", decoded.QueryStatus)
	}

	// Data is null when there are no indicators, which decodes as an empty list.
	var rawIndicators []jsontext.Value
	if err := json.Unmarshal(decoded.Data, &rawIndicators); 0 != len(decoded.Data) && nil != err {
		return nil, fmt.Errorf("decoding ThreatFox indicators: %w", err)
	}

	return aggregator.ConvertEntries(ctx, feed.logger, SOURCE_NAME, rawIndicators, newSighting), nil
}

// newSighting converts one raw ThreatFox indicator into a sighting. It returns
// aggregator.ErrUnsupportedEntry for an indicator that isn't an ip:port.
func newSighting(rawIndicator jsontext.Value) (aggregator.Sighting, error) {
	var decoded indicator
	if err := json.Unmarshal(rawIndicator, &decoded); nil != err {
		return aggregator.Sighting{}, fmt.Errorf("decoding indicator: %w", err)
	}

	if IP_PORT_TYPE != decoded.IOCType {
		return aggregator.Sighting{}, aggregator.ErrUnsupportedEntry
	}

	// An ip:port indicator has exactly one colon, so IPv6 addresses aren't accepted here.
	rawAddress, rawPort, isAddressAndPort := strings.Cut(decoded.IOC, ":")
	if !isAddressAndPort {
		return aggregator.Sighting{}, fmt.Errorf("indicator %q isn't an address and port", decoded.IOC)
	}

	address, err := aggregator.ParseAddress(rawAddress)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing indicator %q: %w", decoded.IOC, err)
	}

	// Ports are 16-bit numbers.
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing port %q: %w", rawPort, err)
	}

	// time.Parse keeps the wall-clock time and the named zone, which ThreatFox gives as UTC.
	firstSeen, err := time.Parse(TIME_LAYOUT, decoded.FirstSeen)
	if nil != err {
		return aggregator.Sighting{}, fmt.Errorf("parsing first_seen %q: %w", decoded.FirstSeen, err)
	}

	family := decoded.MalwarePrintable
	if "" == family {
		family = UNKNOWN_MALWARE
	}

	report := aggregator.NewReport(decoded.ID, []string{family}, Data{
		IOC:             decoded.IOC,
		Port:            uint16(port),
		ThreatType:      decoded.ThreatType,
		Malware:         decoded.MalwarePrintable,
		MalwareMalpedia: decoded.MalwareMalpedia,
		ConfidenceLevel: decoded.ConfidenceLevel,
		FirstSeen:       firstSeen.UTC(),
		Reference:       decoded.Reference,
		Tags:            aggregator.SortedUnique(decoded.Tags),
	})

	return aggregator.Sighting{Address: address, Report: report}, nil
}
