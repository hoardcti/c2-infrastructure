// Package internetdb is the Shodan InternetDB enricher: open ports, hostnames, software (CPEs),
// tags and vulnerabilities for an address, from Shodan's free, keyless InternetDB API.
//
// InternetDB is updated about once a week, so a weekly refresh is enough. It's free for
// non-commercial use.
//
// It's a package of its own, imported only by the command, because it hides InternetDB's
// response types from the rest of the program (GO-PKG-004, reason 3), like every source.
package internetdb

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The InternetDB API.
const (
	// SOURCE_NAME names InternetDB in sources.json and in every record.
	SOURCE_NAME = "internetdb"
	// MAX_RESPONSE_BYTES bounds a response, which is a few hundred bytes for most addresses.
	MAX_RESPONSE_BYTES = 1 << 20
)

// Enricher looks addresses up in InternetDB. Build one with New.
type Enricher struct {
	// baseURL is the API's base URL; the address is appended to it.
	baseURL *url.URL
	// upstream sends the requests.
	upstream *aggregator.Upstream
}

// New builds the InternetDB enricher from its sources.json entry.
func New(config aggregator.SourceConfig, upstream *aggregator.Upstream) (*Enricher, error) {
	endpoint, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	return &Enricher{baseURL: endpoint, upstream: upstream}, nil
}

// Data is what an InternetDB observation stores, and also how a response is decoded: the
// upstream's field names are the stored ones. Every list is sorted, so a reordered response
// isn't stored as a change.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to name the
// field's JSON key.
type Data struct {
	// Ports are the open ports Shodan found.
	Ports []int `json:"ports"`
	// Hostnames are the address's hostnames.
	Hostnames []string `json:"hostnames"`
	// CPEs identify the software found, such as "cpe:/a:helpsystems:cobalt_strike".
	CPEs []string `json:"cpes"`
	// Tags are Shodan's tags, such as "c2" or "self-signed".
	Tags []string `json:"tags"`
	// Vulns are the CVE identifiers the software is likely vulnerable to.
	Vulns []string `json:"vulns"`
}

// Lookup returns InternetDB's report on address, or no reports when InternetDB has no
// information about it (404 Not Found).
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	// JoinPath escapes the address, so it can't change the rest of the URL.
	lookupURL := enricher.baseURL.JoinPath(address.String()).String()

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{Method: http.MethodGet, URL: lookupURL}, MAX_RESPONSE_BYTES)
	if aggregator.IsNotFound(err) {
		return nil, nil
	}

	if nil != err {
		return nil, fmt.Errorf("querying InternetDB: %w", err)
	}

	return newReports(body)
}

// newReports decodes an InternetDB response into its report, with every list sorted so a
// reordered response isn't stored as a change.
func newReports(body []byte) ([]aggregator.Report, error) {
	var decoded Data
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding InternetDB response: %w", err)
	}

	return []aggregator.Report{aggregator.NewReport("", nil, Data{
		Ports:     aggregator.SortedUnique(decoded.Ports),
		Hostnames: aggregator.SortedUnique(decoded.Hostnames),
		CPEs:      aggregator.SortedUnique(decoded.CPEs),
		Tags:      aggregator.SortedUnique(decoded.Tags),
		Vulns:     aggregator.SortedUnique(decoded.Vulns),
	})}, nil
}
