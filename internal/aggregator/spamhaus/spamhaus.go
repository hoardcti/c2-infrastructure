// Package spamhaus is the Spamhaus DROP enricher: it reports when an address lies in a netblock
// on Spamhaus's "Don't Route Or Peer" list of hijacked networks and networks run by criminals.
//
// The IPv4 and IPv6 lists are downloaded once, at the first lookup of a run, and every address
// is then matched locally, so the enricher makes two requests a run whatever the number of
// addresses. Spamhaus asks for the list to be fetched at most once an hour, which an hourly
// run respects. Spamhaus must be credited when the data is used.
//
// It's a package of its own, imported only by the command, because it hides the downloaded
// lists, which no other code may change (GO-PKG-004, reason 3), like every source.
package spamhaus

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/netip"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The Spamhaus DROP lists.
const (
	// SOURCE_NAME names Spamhaus DROP in sources.json and in every record.
	SOURCE_NAME = "spamhaus"
	// MAX_RESPONSE_BYTES bounds a list, which is about 100 KiB.
	MAX_RESPONSE_BYTES = 8 << 20
	// METADATA_TYPE is the type of the line that describes the list rather than a netblock.
	METADATA_TYPE = "metadata"
)

// Options are the enricher's own settings in sources.json.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type Options struct {
	// IPv6URL is the IPv6 list's download; the source's url is the IPv4 list's.
	IPv6URL string `json:"ipv6_url"`
}

// Enricher matches addresses against the DROP lists. Build one with New. It isn't safe for
// concurrent use: the aggregator looks addresses up one at a time.
type Enricher struct {
	// listURLs are the IPv4 and IPv6 lists' downloads.
	listURLs []string
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// netblocks holds every listed netblock once the lists are loaded.
	netblocks []Netblock
	// isLoaded is true once a load has been attempted, so the lists are downloaded at most once.
	isLoaded bool
	// loadErr is the error of that load, returned by every lookup if it failed.
	loadErr error
}

// New builds the Spamhaus enricher from its sources.json entry. Its options must give the
// IPv6 list's URL.
func New(config aggregator.SourceConfig, upstream *aggregator.Upstream) (*Enricher, error) {
	ipv4URL, err := aggregator.ParseUpstreamURL(config.URL)
	if nil != err {
		return nil, fmt.Errorf("checking url: %w", err)
	}

	var options Options
	if err = aggregator.DecodeOptions(config.Options, &options); nil != err {
		return nil, fmt.Errorf("checking options: %w", err)
	}

	ipv6URL, err := aggregator.ParseUpstreamURL(options.IPv6URL)
	if nil != err {
		return nil, fmt.Errorf("checking ipv6_url: %w", err)
	}

	return &Enricher{listURLs: []string{ipv4URL.String(), ipv6URL.String()}, upstream: upstream}, nil
}

// Netblock is one line of a DROP list, and also what a Spamhaus observation stores: the
// upstream's field names are the stored ones.
type Netblock struct {
	// CIDR is the listed netblock, such as "1.10.16.0/20".
	CIDR string `json:"cidr"`
	// SBLID is the Spamhaus Block List record that explains the listing, such as "SBL256894".
	SBLID string `json:"sblid"`
	// RIR is the registry that allocated the netblock, such as "apnic".
	RIR string `json:"rir"`
	// prefix is the parsed CIDR. It's unexported, so encoding/json ignores it.
	prefix netip.Prefix
}

// Lookup returns one report for each listed netblock that contains address, keyed by the
// netblock, or no reports if none does.
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	if !enricher.isLoaded {
		enricher.netblocks, enricher.loadErr = enricher.load(ctx)
		enricher.isLoaded = true
	}

	if nil != enricher.loadErr {
		return nil, enricher.loadErr
	}

	var reports []aggregator.Report

	for _, netblock := range enricher.netblocks {
		if netblock.prefix.Contains(address) {
			reports = append(reports, aggregator.NewReport(netblock.CIDR, nil, netblock))
		}
	}

	return reports, nil
}

// load downloads both lists and returns every netblock in them.
func (enricher *Enricher) load(ctx context.Context) ([]Netblock, error) {
	var netblocks []Netblock

	for _, listURL := range enricher.listURLs {
		body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
			Method: http.MethodGet,
			URL:    listURL,
		}, MAX_RESPONSE_BYTES)
		if nil != err {
			return nil, fmt.Errorf("downloading DROP list %q: %w", listURL, err)
		}

		listed, err := parseList(body)
		if nil != err {
			return nil, fmt.Errorf("parsing DROP list %q: %w", listURL, err)
		}

		netblocks = append(netblocks, listed...)
	}

	return netblocks, nil
}

// parseList parses a DROP list: one JSON object per line, each a netblock, apart from a final
// metadata line. A list without netblocks is refused, because DROP is never empty and an empty
// download would silently stop every match.
func parseList(body []byte) ([]Netblock, error) {
	var netblocks []Netblock

	// A Scanner reads the body one line at a time; Scan returns false at the end.
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := bytes.TrimSpace(scanner.Bytes())
		if 0 == len(line) {
			continue
		}

		var decoded struct {
			// Netblock is embedded: a field with only a type adds the embedded struct's fields
			// to this one. The inline struct tag tells encoding/json to read them from the same
			// JSON object.
			Netblock `json:",inline"`
			// Type is "metadata" on the line that describes the list.
			Type string `json:"type"`
		}
		if err := json.Unmarshal(line, &decoded); nil != err {
			return nil, fmt.Errorf("decoding line %d: %w", lineNumber, err)
		}

		if METADATA_TYPE == decoded.Type {
			continue
		}

		prefix, err := netip.ParsePrefix(decoded.CIDR)
		if nil != err {
			return nil, fmt.Errorf("parsing line %d: %w", lineNumber, err)
		}

		decoded.prefix = prefix.Masked()
		netblocks = append(netblocks, decoded.Netblock)
	}

	if err := scanner.Err(); nil != err {
		return nil, fmt.Errorf("reading list: %w", err)
	}

	if 0 == len(netblocks) {
		return nil, errors.New("list has no netblocks")
	}

	return netblocks, nil
}
