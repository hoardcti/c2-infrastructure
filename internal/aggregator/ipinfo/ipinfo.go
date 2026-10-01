// Package ipinfo is the IPinfo Lite enricher: the autonomous system and country of an
// address, from IPinfo's free Lite API.
//
// IPinfo Lite data is licensed under CC BY-SA 4.0, which requires crediting IPinfo.
//
// It's a package of its own, imported only by the command, because it hides state the rest of
// the program mustn't touch: the IPinfo token and IPinfo's response types (GO-PKG-004,
// reason 3), like every source.
package ipinfo

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The IPinfo Lite API.
const (
	// SOURCE_NAME names IPinfo in sources.json and in every record.
	SOURCE_NAME = "ipinfo"
	// MAX_RESPONSE_BYTES bounds a response, which is a few hundred bytes.
	MAX_RESPONSE_BYTES = 1 << 20
)

// Enricher looks addresses up in IPinfo Lite. Build one with New.
type Enricher struct {
	// baseURL is the API's base URL; the address is appended to it.
	baseURL *url.URL
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// token is the IPinfo access token.
	token aggregator.APIKey
}

// New builds the IPinfo enricher from its sources.json entry. token must be set.
func New(
	config aggregator.SourceConfig,
	upstream *aggregator.Upstream,
	token aggregator.APIKey,
) (*Enricher, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	if "" == token {
		return nil, errors.New("the IPinfo token is required")
	}

	return &Enricher{baseURL: endpoint, upstream: upstream, token: token}, nil
}

// Data is what an IPinfo observation stores, and also how a response is decoded: the
// upstream's field names are the stored ones.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to name the
// field's JSON key.
type Data struct {
	// ASN is the autonomous system number, such as "AS45090".
	ASN string `json:"asn"`
	// ASName is the autonomous system's name.
	ASName string `json:"as_name"`
	// ASDomain is the autonomous system owner's domain.
	ASDomain string `json:"as_domain"`
	// CountryCode is the two-letter ISO 3166 country code.
	CountryCode string `json:"country_code"`
	// Country is the country's name.
	Country string `json:"country"`
	// ContinentCode is the two-letter continent code.
	ContinentCode string `json:"continent_code"`
	// Continent is the continent's name.
	Continent string `json:"continent"`
}

// Lookup returns IPinfo's report on address.
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	// JoinPath escapes the address, so it can't change the rest of the URL.
	lookupURL := enricher.baseURL.JoinPath(address.String()).String()

	// The token goes in a header, never in the URL, so it can't leak through URLs in logs or
	// errors.
	header := http.Header{}
	header.Set("Accept", "application/json")
	header.Set("Authorization", "Bearer "+string(enricher.token))

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    lookupURL,
		Header: header,
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("querying IPinfo: %w", err)
	}

	return newReports(body)
}

// newReports decodes an IPinfo response into its report.
func newReports(body []byte) ([]aggregator.Report, error) {
	var decoded Data
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding IPinfo response: %w", err)
	}

	return []aggregator.Report{aggregator.NewReport("", nil, decoded)}, nil
}
