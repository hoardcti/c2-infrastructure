// Package virustotal is the VirusTotal enricher: security vendors' verdicts, community
// reputation, network ownership and TLS fingerprint of an address, from VirusTotal's v3 API.
//
// The free public API allows 4 requests a minute and 500 a day, so sources.json spreads the
// lookups over runs. WHOIS and RDAP data aren't stored: they hold personal contact details and
// change with every registry update. Analysis dates aren't stored either, so a re-analysis
// with the same verdicts isn't recorded as a change.
//
// It's a package of its own, imported only by the command, because it hides state the rest of
// the program mustn't touch: the VirusTotal key and VirusTotal's response types (GO-PKG-004,
// reason 3), like every source.
package virustotal

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

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The VirusTotal API.
const (
	// SOURCE_NAME names VirusTotal in sources.json and in every record.
	SOURCE_NAME = "virustotal"
	// MAX_RESPONSE_BYTES bounds a response, which is about 20 KiB for most addresses.
	MAX_RESPONSE_BYTES = 4 << 20
)

// Verdict categories in last_analysis_results that mean a vendor flags the address.
const (
	// MALICIOUS_CATEGORY is a vendor's "malicious" verdict.
	MALICIOUS_CATEGORY = "malicious"
	// SUSPICIOUS_CATEGORY is a vendor's "suspicious" verdict.
	SUSPICIOUS_CATEGORY = "suspicious"
)

// Enricher looks addresses up in VirusTotal. Build one with New.
type Enricher struct {
	// baseURL is the ip_addresses endpoint; the address is appended to it.
	baseURL *url.URL
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// apiKey is the VirusTotal API key.
	apiKey aggregator.APIKey
}

// New builds the VirusTotal enricher from its sources.json entry. apiKey must be set.
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
		return nil, errors.New("the VirusTotal API key is required")
	}

	return &Enricher{baseURL: endpoint, upstream: upstream, apiKey: apiKey}, nil
}

// response mirrors the parts of a VirusTotal IP address report that are stored. Upstream fields
// that aren't stored are left out, and encoding/json ignores them when decoding.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type response struct {
	// Data is the IP address object.
	Data struct {
		// Attributes holds the report.
		Attributes attributes `json:"attributes"`
	} `json:"data"`
}

// attributes mirrors the stored attributes of a VirusTotal IP address object.
type attributes struct {
	// ASOwner is the autonomous system's owner.
	ASOwner string `json:"as_owner"`
	// ASN is the autonomous system number.
	ASN int `json:"asn"`
	// Network is the routed prefix the address belongs to.
	Network string `json:"network"`
	// Country is the two-letter country code.
	Country string `json:"country"`
	// Continent is the two-letter continent code.
	Continent string `json:"continent"`
	// RegionalInternetRegistry is the registry that allocated the address, such as "APNIC".
	RegionalInternetRegistry string `json:"regional_internet_registry"`
	// Reputation is VirusTotal's community score; negative means malicious.
	Reputation int `json:"reputation"`
	// LastAnalysisStats counts the vendors' verdicts by category.
	LastAnalysisStats AnalysisStats `json:"last_analysis_stats"`
	// LastAnalysisResults holds each vendor's verdict, keyed by vendor name.
	LastAnalysisResults map[string]analysisResult `json:"last_analysis_results"`
	// TotalVotes counts the community's votes.
	TotalVotes Votes `json:"total_votes"`
	// Tags are VirusTotal's tags for the address.
	Tags []string `json:"tags"`
	// JARM is the TLS server fingerprint VirusTotal last saw.
	JARM string `json:"jarm"`
	// CrowdsourcedContext holds notes from threat-intelligence partners.
	CrowdsourcedContext []PartnerNote `json:"crowdsourced_context"`
}

// analysisResult mirrors one vendor's verdict.
type analysisResult struct {
	// Category is the normalised verdict, such as "malicious" or "harmless".
	Category string `json:"category"`
	// Result is the vendor's own verdict text, such as "malware".
	Result string `json:"result"`
}

// AnalysisStats counts the vendors' verdicts by category. It's stored as VirusTotal sends it.
type AnalysisStats struct {
	// Malicious counts "malicious" verdicts.
	Malicious int `json:"malicious"`
	// Suspicious counts "suspicious" verdicts.
	Suspicious int `json:"suspicious"`
	// Undetected counts vendors that found nothing.
	Undetected int `json:"undetected"`
	// Harmless counts "harmless" verdicts.
	Harmless int `json:"harmless"`
	// Timeout counts vendors that didn't answer.
	Timeout int `json:"timeout"`
}

// Votes counts the community's votes. It's stored as VirusTotal sends it.
type Votes struct {
	// Harmless counts "harmless" votes.
	Harmless int `json:"harmless"`
	// Malicious counts "malicious" votes.
	Malicious int `json:"malicious"`
}

// PartnerNote is a note from a threat-intelligence partner, from VirusTotal's
// crowdsourced_context. It's stored as VirusTotal sends it, except for the details text, which
// is long and adds little to the title, and the timestamp, which changes when the note is
// refreshed.
type PartnerNote struct {
	// Source names the partner, such as "Cluster25".
	Source string `json:"source"`
	// Title summarises the note, such as "Activity related to COBALTSTRIKE".
	Title string `json:"title"`
	// Severity is the partner's rating, such as "high"; empty when not given.
	Severity string `json:"severity,omitzero"`
}

// Data is what a VirusTotal observation stores.
type Data struct {
	// ASOwner is the autonomous system's owner.
	ASOwner string `json:"as_owner"`
	// ASN is the autonomous system number.
	ASN int `json:"asn"`
	// Network is the routed prefix the address belongs to.
	Network string `json:"network"`
	// Country is the two-letter country code.
	Country string `json:"country"`
	// Continent is the two-letter continent code.
	Continent string `json:"continent"`
	// RegionalInternetRegistry is the registry that allocated the address.
	RegionalInternetRegistry string `json:"regional_internet_registry"`
	// Reputation is VirusTotal's community score; negative means malicious.
	Reputation int `json:"reputation"`
	// AnalysisStats counts the vendors' verdicts by category.
	AnalysisStats AnalysisStats `json:"analysis_stats"`
	// FlaggingVendors lists the vendors with a malicious or suspicious verdict, sorted.
	FlaggingVendors []Verdict `json:"flagging_vendors"`
	// TotalVotes counts the community's votes.
	TotalVotes Votes `json:"total_votes"`
	// Tags are VirusTotal's tags, sorted.
	Tags []string `json:"tags"`
	// JARM is the TLS server fingerprint VirusTotal last saw; empty when none.
	JARM string `json:"jarm,omitzero"`
	// CrowdsourcedContext holds partners' notes, sorted by source and title.
	CrowdsourcedContext []PartnerNote `json:"crowdsourced_context"`
}

// Verdict is one vendor's malicious or suspicious verdict.
type Verdict struct {
	// Vendor is the vendor's name.
	Vendor string `json:"vendor"`
	// Category is "malicious" or "suspicious".
	Category string `json:"category"`
	// Result is the vendor's own verdict text.
	Result string `json:"result"`
}

// Lookup returns VirusTotal's report on address, or no reports if VirusTotal doesn't know it
// (404 Not Found).
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	// JoinPath escapes the address, so it can't change the rest of the URL.
	lookupURL := enricher.baseURL.JoinPath(address.String()).String()

	// The key goes in a header, never in the URL, so it can't leak through URLs in logs or
	// errors.
	header := http.Header{}
	header.Set("Accept", "application/json")
	header.Set("X-Apikey", string(enricher.apiKey))

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    lookupURL,
		Header: header,
	}, MAX_RESPONSE_BYTES)
	if aggregator.IsNotFound(err) {
		return nil, nil
	}

	if nil != err {
		return nil, fmt.Errorf("querying VirusTotal: %w", err)
	}

	return newReports(body)
}

// newReports decodes a VirusTotal IP address report into its report.
func newReports(body []byte) ([]aggregator.Report, error) {
	var decoded response
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding VirusTotal response: %w", err)
	}

	return []aggregator.Report{aggregator.NewReport("", nil, newData(decoded.Data.Attributes))}, nil
}

// newData keeps the stored parts of a report, with every list sorted so a reordered response
// isn't stored as a change.
func newData(report attributes) Data {
	verdicts := []Verdict{}

	for vendor, result := range report.LastAnalysisResults {
		if MALICIOUS_CATEGORY == result.Category || SUSPICIOUS_CATEGORY == result.Category {
			verdicts = append(verdicts, Verdict{Vendor: vendor, Category: result.Category, Result: result.Result})
		}
	}

	// Map iteration order is random in Go, so the verdicts are sorted by vendor.
	slices.SortFunc(verdicts, func(first, second Verdict) int {
		return strings.Compare(first.Vendor, second.Vendor)
	})

	contexts := slices.Clone(report.CrowdsourcedContext)
	slices.SortFunc(contexts, func(first, second PartnerNote) int {
		return strings.Compare(first.Source+"\x00"+first.Title, second.Source+"\x00"+second.Title)
	})

	return Data{
		ASOwner:                  report.ASOwner,
		ASN:                      report.ASN,
		Network:                  report.Network,
		Country:                  report.Country,
		Continent:                report.Continent,
		RegionalInternetRegistry: report.RegionalInternetRegistry,
		Reputation:               report.Reputation,
		AnalysisStats:            report.LastAnalysisStats,
		FlaggingVendors:          verdicts,
		TotalVotes:               report.TotalVotes,
		Tags:                     aggregator.SortedUnique(report.Tags),
		JARM:                     report.JARM,
		CrowdsourcedContext:      slices.Compact(contexts),
	}
}
