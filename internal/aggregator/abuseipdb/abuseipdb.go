// Package abuseipdb is the AbuseIPDB enricher: the abuse confidence score, report counts and
// network usage of an address, from AbuseIPDB's v2 check endpoint.
//
// The free plan allows 1,000 checks a day, so sources.json spreads the lookups over runs. When
// the daily quota is used up, AbuseIPDB answers 429 with a Retry-After of hours, which stops
// the source for the rest of the run.
//
// It's a package of its own, imported only by the command, because it hides state the rest of
// the program mustn't touch: the AbuseIPDB key and AbuseIPDB's response types (GO-PKG-004,
// reason 3), like every source.
package abuseipdb

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The AbuseIPDB API.
const (
	// SOURCE_NAME names AbuseIPDB in sources.json and in every record.
	SOURCE_NAME = "abuseipdb"
	// MAX_RESPONSE_BYTES bounds a response, which is under 1 KiB without verbose reports.
	MAX_RESPONSE_BYTES = 1 << 20
	// DEFAULT_MAX_AGE_IN_DAYS is how far back reports are counted when the options don't say.
	DEFAULT_MAX_AGE_IN_DAYS = 90
	// MAX_MAX_AGE_IN_DAYS is the longest period AbuseIPDB accepts.
	MAX_MAX_AGE_IN_DAYS = 365
)

// Options are the enricher's own settings in sources.json.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type Options struct {
	// MaxAgeInDays is how far back reports are counted, from 1 to 365.
	MaxAgeInDays int `json:"max_age_in_days"`
}

// Enricher checks addresses with AbuseIPDB. Build one with New.
type Enricher struct {
	// checkURL is the check endpoint.
	checkURL *url.URL
	// maxAgeInDays is Options.MaxAgeInDays.
	maxAgeInDays int
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// apiKey is the AbuseIPDB v2 key.
	apiKey aggregator.APIKey
}

// New builds the AbuseIPDB enricher from its sources.json entry. apiKey must be set.
func New(
	config aggregator.SourceConfig,
	upstream *aggregator.Upstream,
	apiKey aggregator.APIKey,
) (*Enricher, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	options := Options{MaxAgeInDays: DEFAULT_MAX_AGE_IN_DAYS}
	if err := aggregator.DecodeOptions(config.Options, &options); nil != err {
		return nil, fmt.Errorf("checking options: %w", err)
	}

	if options.MaxAgeInDays < 1 || options.MaxAgeInDays > MAX_MAX_AGE_IN_DAYS {
		return nil, fmt.Errorf("max_age_in_days is %d, want 1 to %d", options.MaxAgeInDays, MAX_MAX_AGE_IN_DAYS)
	}

	if "" == apiKey {
		return nil, errors.New("the AbuseIPDB API key is required")
	}

	return &Enricher{
		checkURL:     endpoint,
		maxAgeInDays: options.MaxAgeInDays,
		upstream:     upstream,
		apiKey:       apiKey,
	}, nil
}

// response mirrors an AbuseIPDB check response. Upstream fields that aren't stored are left
// out, and encoding/json ignores them when decoding. The field names are AbuseIPDB's own.
type response struct {
	// Data is the check result.
	Data struct {
		// AbuseConfidenceScore is AbuseIPDB's confidence, from 0 to 100, that the address is
		// abusive.
		AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		// TotalReports counts the reports within the period.
		TotalReports int `json:"totalReports"`
		// NumDistinctUsers counts the users who reported it.
		NumDistinctUsers int `json:"numDistinctUsers"`
		// LastReportedAt is when it was last reported, or null if never.
		LastReportedAt *time.Time `json:"lastReportedAt"`
		// IsWhitelisted is true for addresses AbuseIPDB knows to be benign, or null.
		IsWhitelisted *bool `json:"isWhitelisted"`
		// IsTor is true for Tor exit nodes.
		IsTor bool `json:"isTor"`
		// UsageType describes the network, such as a hosting provider or a fixed-line ISP.
		UsageType string `json:"usageType"`
		// ISP is the internet service provider.
		ISP string `json:"isp"`
		// Domain is the ISP's domain.
		Domain string `json:"domain"`
		// CountryCode is the two-letter country code.
		CountryCode string `json:"countryCode"`
		// Hostnames are the address's reverse DNS names.
		Hostnames []string `json:"hostnames"`
	} `json:"data"`
}

// Data is what an AbuseIPDB observation stores.
type Data struct {
	// AbuseConfidenceScore is AbuseIPDB's confidence, from 0 to 100, that the address is
	// abusive.
	AbuseConfidenceScore int `json:"abuse_confidence_score"`
	// TotalReports counts the reports within MaxAgeInDays.
	TotalReports int `json:"total_reports"`
	// DistinctReporters counts the users who reported it.
	DistinctReporters int `json:"distinct_reporters"`
	// LastReportedAt is when it was last reported, or nil (stored as null) if never.
	LastReportedAt *time.Time `json:"last_reported_at"`
	// MaxAgeInDays is the period the counts cover.
	MaxAgeInDays int `json:"max_age_in_days"`
	// IsWhitelisted is true for addresses AbuseIPDB knows to be benign, or nil (stored as null)
	// when it has no opinion.
	IsWhitelisted *bool `json:"is_whitelisted"`
	// IsTor is true for Tor exit nodes.
	IsTor bool `json:"is_tor"`
	// UsageType describes the network, such as a hosting provider or a fixed-line ISP, in
	// AbuseIPDB's own words.
	UsageType string `json:"usage_type"`
	// ISP is the internet service provider.
	ISP string `json:"isp"`
	// Domain is the ISP's domain.
	Domain string `json:"domain"`
	// CountryCode is the two-letter country code.
	CountryCode string `json:"country_code"`
	// Hostnames are the address's reverse DNS names, sorted.
	Hostnames []string `json:"hostnames"`
}

// Lookup returns AbuseIPDB's check of address.
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	// net/url escapes the query values, so the address can't change the rest of the URL. The
	// URL is a copy, so the enricher's own is never changed.
	query := url.Values{}
	query.Set("ipAddress", address.String())
	query.Set("maxAgeInDays", strconv.Itoa(enricher.maxAgeInDays))

	checkURL := *enricher.checkURL
	checkURL.RawQuery = query.Encode()

	// The key goes in a header, never in the URL, so it can't leak through URLs in logs or
	// errors.
	header := http.Header{}
	header.Set("Accept", "application/json")
	header.Set("Key", string(enricher.apiKey))

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    checkURL.String(),
		Header: header,
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("querying AbuseIPDB: %w", err)
	}

	return newReports(body, enricher.maxAgeInDays)
}

// newReports decodes an AbuseIPDB check response into its report. maxAgeInDays is the period
// the check covered, which is stored with the counts.
func newReports(body []byte, maxAgeInDays int) ([]aggregator.Report, error) {
	var decoded response
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding AbuseIPDB response: %w", err)
	}

	check := decoded.Data

	var lastReportedAt *time.Time
	if nil != check.LastReportedAt {
		lastReportedAt = new(check.LastReportedAt.UTC())
	}

	return []aggregator.Report{aggregator.NewReport("", nil, Data{
		AbuseConfidenceScore: check.AbuseConfidenceScore,
		TotalReports:         check.TotalReports,
		DistinctReporters:    check.NumDistinctUsers,
		LastReportedAt:       lastReportedAt,
		MaxAgeInDays:         maxAgeInDays,
		IsWhitelisted:        check.IsWhitelisted,
		IsTor:                check.IsTor,
		UsageType:            check.UsageType,
		ISP:                  check.ISP,
		Domain:               check.Domain,
		CountryCode:          check.CountryCode,
		Hostnames:            aggregator.SortedUnique(check.Hostnames),
	})}, nil
}
