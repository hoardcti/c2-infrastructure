package aggregator

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The ThreatFox API.
const (
	// THREATFOX_SOURCE_NAME names the ThreatFox API in sources.json and in published results.
	THREATFOX_SOURCE_NAME = "threatfox"
	// MAX_THREATFOX_RESPONSE_BYTES bounds a ThreatFox response. A query returns at most 1,000
	// indicators, about 1 MiB.
	MAX_THREATFOX_RESPONSE_BYTES = 32 << 20
	// THREATFOX_TIME_LAYOUT matches ThreatFox timestamps, such as "2026-05-19 10:11:12 UTC".
	THREATFOX_TIME_LAYOUT = "2006-01-02 15:04:05 MST"
	// THREATFOX_OK_STATUS is the query_status of a successful ThreatFox query.
	THREATFOX_OK_STATUS = "ok"
	// THREATFOX_IP_PORT_TYPE is the ioc_type of an "address:port" indicator, the only kind
	// that describes an IP address.
	THREATFOX_IP_PORT_TYPE = "ip:port"
	// THREATFOX_UNKNOWN_MALWARE is the malware family recorded when ThreatFox gives none.
	THREATFOX_UNKNOWN_MALWARE = "unknown"
)

// threatFoxResponse mirrors a ThreatFox API response.
//
// The struct tags set the upstream JSON key each field is read from.
type threatFoxResponse struct {
	// QueryStatus is "ok" on success, or a code such as "unknown_auth_key".
	QueryStatus string `json:"query_status"`
	// Data holds the indicators, or null when there are none. Each is kept as raw JSON and
	// decoded on its own, so a malformed indicator is skipped instead of failing the query.
	Data []jsontext.Value `json:"data"`
}

// threatFoxIndicator mirrors one indicator in a ThreatFox response. Upstream fields that
// aren't published are left out, and encoding/json ignores them when decoding.
type threatFoxIndicator struct {
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
	// MalwareMalpedia is the family's Malpedia page. It's published, never fetched.
	MalwareMalpedia string `json:"malware_malpedia"`
	// FirstSeen is when ThreatFox first saw the indicator, in THREATFOX_TIME_LAYOUT.
	FirstSeen string `json:"first_seen"`
	// Reference is a URL the reporter cited. It's nil when the upstream sends null, which is
	// published as null rather than as an empty string. It's published, never fetched.
	Reference *string `json:"reference"`
}

// threatFoxMetadata is the published metadata of a ThreatFox sighting.
//
// Keys and field order match the files published so far, so existing data and new data look
// the same.
type threatFoxMetadata struct {
	// FirstSeen is when ThreatFox first saw the indicator.
	FirstSeen isoTime `json:"firstSeen"`
	// Port is the port part of the indicator, as ThreatFox wrote it.
	Port string `json:"port"`
	// Reference is a URL the reporter cited, or nil (published as null).
	Reference *string `json:"reference"`
	// MalwareMalpedia is the malware family's Malpedia page.
	MalwareMalpedia string `json:"malware_malpedia"`
	// ID is ThreatFox's identifier for the indicator.
	ID string `json:"id"`
	// IOC is the whole indicator, such as "1.2.3.4:443".
	IOC string `json:"ioc"`
	// ThreatType is the kind of threat, such as "botnet_cc".
	ThreatType string `json:"threat_type"`
}

// extractThreatFox queries the ThreatFox API with the source's query and returns a payload for
// every ip:port indicator in the response. Other indicators are skipped, and malformed ones are
// skipped with a warning.
func (aggregator *Aggregator) extractThreatFox(
	ctx context.Context,
	source Source,
) ([]Payload, error) {
	// Only an invalid string (bad UTF-8) in the query can make encoding fail.
	requestBody, err := json.Marshal(source.Query)
	if nil != err {
		return nil, fmt.Errorf("encoding query: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		source.URL,
		bytes.NewReader(requestBody),
	)
	if nil != err {
		return nil, fmt.Errorf("building request: %w", err)
	}

	// The key goes in a header, never in the URL, so it can't leak through URLs in logs or
	// errors.
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Auth-Key", string(aggregator.abusechAPIKey))

	responseBody, err := aggregator.send(request, MAX_THREATFOX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("querying ThreatFox: %w", err)
	}

	return aggregator.convertThreatFoxResponse(ctx, responseBody)
}

// convertThreatFoxResponse returns a payload for every ip:port indicator in a ThreatFox
// response body. It fails if the query itself failed.
func (aggregator *Aggregator) convertThreatFoxResponse(
	ctx context.Context,
	responseBody []byte,
) ([]Payload, error) {
	var response threatFoxResponse
	if err := json.Unmarshal(responseBody, &response); nil != err {
		return nil, fmt.Errorf("decoding ThreatFox response: %w", err)
	}

	if THREATFOX_OK_STATUS != response.QueryStatus {
		return nil, fmt.Errorf("ThreatFox query failed with status %q", response.QueryStatus)
	}

	// Every indicator records when this run collected it, not when ThreatFox first saw it.
	ingestedAt := isoTime(aggregator.now().UTC())

	// The function literal is a closure: it uses ingestedAt from extractThreatFox.
	convert := func(rawIndicator jsontext.Value) (Payload, error) {
		return newThreatFoxPayload(rawIndicator, ingestedAt)
	}

	indicators := response.Data

	return convertEntries(ctx, aggregator.logger, THREATFOX_SOURCE_NAME, indicators, convert), nil
}

// newThreatFoxPayload converts one raw ThreatFox indicator into a payload. It returns
// errUnsupportedEntry for an indicator that isn't an ip:port.
func newThreatFoxPayload(rawIndicator jsontext.Value, ingestedAt isoTime) (Payload, error) {
	var indicator threatFoxIndicator
	if err := json.Unmarshal(rawIndicator, &indicator); nil != err {
		return Payload{}, fmt.Errorf("decoding indicator: %w", err)
	}

	if THREATFOX_IP_PORT_TYPE != indicator.IOCType {
		return Payload{}, errUnsupportedEntry
	}

	// An ip:port indicator has exactly one colon, so IPv6 addresses aren't accepted here.
	rawAddress, port, isAddressAndPort := strings.Cut(indicator.IOC, ":")
	if !isAddressAndPort {
		return Payload{}, fmt.Errorf("indicator %q isn't an address and port", indicator.IOC)
	}

	address, err := parseAddress(rawAddress)
	if nil != err {
		return Payload{}, err
	}

	// Ports are 16-bit numbers. The port is published as ThreatFox wrote it, so the parsed
	// number is thrown away: _ discards a value on purpose.
	if _, err = strconv.ParseUint(port, 10, 16); nil != err {
		return Payload{}, fmt.Errorf("parsing port %q: %w", port, err)
	}

	// time.Parse keeps the wall-clock time and the named zone, which ThreatFox gives as UTC.
	firstSeen, err := time.Parse(THREATFOX_TIME_LAYOUT, indicator.FirstSeen)
	if nil != err {
		return Payload{}, fmt.Errorf("parsing first_seen %q: %w", indicator.FirstSeen, err)
	}

	family := indicator.MalwarePrintable
	if "" == family {
		family = THREATFOX_UNKNOWN_MALWARE
	}

	metadata := threatFoxMetadata{
		FirstSeen:       isoTime(firstSeen),
		Port:            port,
		Reference:       indicator.Reference,
		MalwareMalpedia: indicator.MalwareMalpedia,
		ID:              indicator.ID,
		IOC:             indicator.IOC,
		ThreatType:      indicator.ThreatType,
	}

	return newPayload(address, THREATFOX_SOURCE_NAME, family, ingestedAt, metadata)
}
