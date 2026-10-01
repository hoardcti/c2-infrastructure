// Package otx is the AlienVault OTX (LevelBlue Open Threat Exchange) enricher: the community
// pulses that mention an address, with their malware families and tags, from OTX's indicator
// API.
//
// One request per address reads the "general" section, which already lists the pulses.
//
// It's a package of its own, imported only by the command, because it hides state the rest of
// the program mustn't touch: the OTX key and OTX's response types (GO-PKG-004, reason 3), like
// every source.
package otx

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The OTX indicator API.
const (
	// SOURCE_NAME names OTX in sources.json and in every record.
	SOURCE_NAME = "otx"
	// MAX_RESPONSE_BYTES bounds a response. Addresses in many pulses give a few hundred KiB.
	MAX_RESPONSE_BYTES = 8 << 20
	// SECTION is the indicator section read: general information and the pulse list.
	SECTION = "general"
	// IPV4_INDICATOR_TYPE is the indicator type in the URL of an IPv4 address.
	IPV4_INDICATOR_TYPE = "IPv4"
	// IPV6_INDICATOR_TYPE is the indicator type in the URL of an IPv6 address.
	IPV6_INDICATOR_TYPE = "IPv6"
	// TIME_LAYOUT matches OTX timestamps, such as "2026-05-20T11:26:07.590000", in UTC.
	TIME_LAYOUT = "2006-01-02T15:04:05"
)

// Enricher looks addresses up in OTX. Build one with New.
type Enricher struct {
	// baseURL is the indicators endpoint; the type, address and section are appended to it.
	baseURL *url.URL
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// apiKey is the OTX key.
	apiKey aggregator.APIKey
}

// New builds the OTX enricher from its sources.json entry. apiKey must be set.
func New(
	config aggregator.SourceConfig,
	upstream *aggregator.Upstream,
	apiKey aggregator.APIKey,
) (*Enricher, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	if "" == apiKey {
		return nil, errors.New("the OTX API key is required")
	}

	return &Enricher{baseURL: endpoint, upstream: upstream, apiKey: apiKey}, nil
}

// response mirrors the parts of an OTX "general" section that are stored. Upstream fields that
// aren't stored are left out, and encoding/json ignores them when decoding.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type response struct {
	// Reputation is OTX's reputation score; 0 when OTX has no opinion.
	Reputation int `json:"reputation"`
	// ASN is the autonomous system and its owner, such as "AS45090 shenzhen tencent".
	ASN string `json:"asn"`
	// CountryCode is the two-letter country code.
	CountryCode string `json:"country_code"`
	// PulseInfo lists the pulses that mention the address.
	PulseInfo struct {
		// Count is the number of pulses, which may exceed the pulses listed.
		Count int `json:"count"`
		// Pulses are the pulses listed.
		Pulses []pulse `json:"pulses"`
	} `json:"pulse_info"`
}

// pulse mirrors the stored fields of one OTX pulse.
type pulse struct {
	// ID is the pulse's identifier.
	ID string `json:"id"`
	// Name is the pulse's title.
	Name string `json:"name"`
	// Created is when the pulse was created, in TIME_LAYOUT.
	Created string `json:"created"`
	// Adversary is the threat actor the pulse names, if any.
	Adversary string `json:"adversary"`
	// TLP is the pulse's Traffic Light Protocol label, such as "green". The key is OTX's own.
	TLP string `json:"TLP"` //nolint:tagliatelle // GO-EXT-002: OTX's own field name.
	// Tags are the author's tags.
	Tags []string `json:"tags"`
	// MalwareFamilies are the malware families the pulse names.
	MalwareFamilies []struct {
		// DisplayName is the family's name, such as "Cobalt Strike".
		DisplayName string `json:"display_name"`
	} `json:"malware_families"`
}

// Data is what an OTX observation stores.
type Data struct {
	// Reputation is OTX's reputation score; 0 when OTX has no opinion.
	Reputation int `json:"reputation"`
	// ASN is the autonomous system and its owner, as OTX writes it.
	ASN string `json:"asn"`
	// CountryCode is the two-letter country code.
	CountryCode string `json:"country_code"`
	// PulseCount is the number of pulses that mention the address.
	PulseCount int `json:"pulse_count"`
	// Pulses are the pulses listed, sorted by ID.
	Pulses []Pulse `json:"pulses"`
}

// Pulse is what an OTX observation stores about one pulse.
type Pulse struct {
	// ID is the pulse's identifier; its page is https://otx.alienvault.com/pulse/<id>.
	ID string `json:"id"`
	// Name is the pulse's title.
	Name string `json:"name"`
	// Created is when the pulse was created; zero, and left out, when OTX gives no valid time.
	Created time.Time `json:"created,omitzero"`
	// Adversary is the threat actor the pulse names; empty when none.
	Adversary string `json:"adversary,omitzero"`
	// TLP is the pulse's Traffic Light Protocol label, such as "green".
	TLP string `json:"tlp"`
	// Tags are the author's tags, sorted.
	Tags []string `json:"tags"`
	// MalwareFamilies are the malware families the pulse names, sorted.
	MalwareFamilies []string `json:"malware_families"`
}

// Lookup returns OTX's report on address.
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	indicatorType := IPV4_INDICATOR_TYPE
	if address.Is6() {
		indicatorType = IPV6_INDICATOR_TYPE
	}

	// JoinPath escapes each part, so the address can't change the rest of the URL.
	lookupURL := enricher.baseURL.JoinPath(indicatorType, address.String(), SECTION).String()

	// The key goes in a header, never in the URL, so it can't leak through URLs in logs or
	// errors.
	header := http.Header{}
	header.Set("Accept", "application/json")
	header.Set("X-OTX-API-KEY", string(enricher.apiKey))

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    lookupURL,
		Header: header,
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("querying OTX: %w", err)
	}

	return newReports(body)
}

// newReports decodes an OTX "general" section into its report, with the pulses sorted so a
// reordered response isn't stored as a change.
func newReports(body []byte) ([]aggregator.Report, error) {
	var decoded response
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding OTX response: %w", err)
	}

	pulses := make([]Pulse, 0, len(decoded.PulseInfo.Pulses))
	for _, listed := range decoded.PulseInfo.Pulses {
		pulses = append(pulses, newPulse(listed))
	}

	// OTX lists pulses in no documented order, so they're sorted to keep the data stable.
	slices.SortFunc(pulses, func(first, second Pulse) int { return strings.Compare(first.ID, second.ID) })

	return []aggregator.Report{aggregator.NewReport("", nil, Data{
		Reputation:  decoded.Reputation,
		ASN:         decoded.ASN,
		CountryCode: decoded.CountryCode,
		PulseCount:  decoded.PulseInfo.Count,
		Pulses:      pulses,
	})}, nil
}

// newPulse keeps the stored parts of a listed pulse. A creation time OTX wrote in another
// format is left out rather than failing the lookup, because it's only context.
func newPulse(listed pulse) Pulse {
	// The blank identifier _ discards the parse error: an unparsable time stays zero.
	created, _ := time.ParseInLocation(TIME_LAYOUT, listed.Created, time.UTC)

	families := make([]string, 0, len(listed.MalwareFamilies))
	for _, family := range listed.MalwareFamilies {
		families = append(families, family.DisplayName)
	}

	return Pulse{
		ID:              listed.ID,
		Name:            listed.Name,
		Created:         created,
		Adversary:       listed.Adversary,
		TLP:             strings.ToLower(listed.TLP),
		Tags:            aggregator.SortedUnique(listed.Tags),
		MalwareFamilies: aggregator.SortedUnique(families),
	}
}
