// Package urlhaus is the URLhaus enricher: malware download URLs that abuse.ch's URLhaus has
// seen hosted on an address, from URLhaus's host lookup API.
//
// URLhaus tracks malware distribution rather than C2, so it never adds addresses to the
// dataset: it only shows when a known C2 server also serves payloads. Its data is published
// under CC0. It uses the same abuse.ch Auth-Key as ThreatFox; abuse.ch limits accounts with
// unusually high query volumes, so sources.json keeps its budget small.
//
// It's a package of its own, imported only by the command, because it hides state the rest of
// the program mustn't touch: the Auth-Key and URLhaus's response types (GO-PKG-004, reason 3),
// like every source.
package urlhaus

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The URLhaus host API.
const (
	// SOURCE_NAME names URLhaus in sources.json and in every record.
	SOURCE_NAME = "urlhaus"
	// MAX_RESPONSE_BYTES bounds a response. A host lists at most a few thousand URLs.
	MAX_RESPONSE_BYTES = 16 << 20
	// OK_STATUS is the query_status of a host URLhaus knows.
	OK_STATUS = "ok"
	// NO_RESULTS_STATUS is the query_status of a host URLhaus doesn't know.
	NO_RESULTS_STATUS = "no_results"
	// UNKNOWN_AUTH_KEY_STATUS is the query_status abuse.ch gives for a key it doesn't know.
	UNKNOWN_AUTH_KEY_STATUS = "unknown_auth_key"
	// TIME_LAYOUT matches URLhaus timestamps, such as "2026-10-01 10:32:09 UTC".
	TIME_LAYOUT = "2006-01-02 15:04:05 MST"
)

// Enricher looks addresses up in URLhaus. Build one with New.
type Enricher struct {
	// hostURL is the host lookup endpoint.
	hostURL string
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// apiKey is the abuse.ch Auth-Key.
	apiKey aggregator.APIKey
}

// New builds the URLhaus enricher from its sources.json entry. apiKey must be set.
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
		return nil, errors.New("the abuse.ch Auth-Key is required")
	}

	return &Enricher{hostURL: endpoint.String(), upstream: upstream, apiKey: apiKey}, nil
}

// response mirrors a URLhaus host response. Upstream fields that aren't stored are left out,
// and encoding/json ignores them when decoding.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type response struct {
	// QueryStatus is "ok", "no_results", or an error code such as "invalid_host".
	QueryStatus string `json:"query_status"`
	// URLhausReference is the host's page on URLhaus.
	URLhausReference string `json:"urlhaus_reference"`
	// FirstSeen is when URLhaus first saw a URL on the host, in TIME_LAYOUT.
	FirstSeen string `json:"firstseen"`
	// URLCount is the number of URLs URLhaus knows on the host, as a string.
	URLCount string `json:"url_count"`
	// Blacklists holds the host's status on other blocklists.
	Blacklists Blacklists `json:"blacklists"`
	// URLs are the malware URLs on the host.
	URLs []hostedURL `json:"urls"`
}

// hostedURL mirrors the stored fields of one URL in a host response.
type hostedURL struct {
	// ID is URLhaus's identifier for the URL.
	ID string `json:"id"`
	// URL is the malware URL. It's stored, never fetched.
	URL string `json:"url"`
	// URLStatus is "online", "offline" or "unknown".
	URLStatus string `json:"url_status"`
	// DateAdded is when the URL was added, in TIME_LAYOUT.
	DateAdded string `json:"date_added"`
	// Threat is the kind of threat, such as "malware_download".
	Threat string `json:"threat"`
	// Tags are the reporter's tags, or null.
	Tags []string `json:"tags"`
}

// Blacklists is the host's status on other blocklists. It's stored as URLhaus sends it.
type Blacklists struct {
	// SpamhausDBL is the host's Spamhaus DBL status, such as "not listed".
	SpamhausDBL string `json:"spamhaus_dbl"`
	// SURBL is the host's SURBL status, such as "not listed".
	SURBL string `json:"surbl"`
}

// Data is what a URLhaus observation stores.
type Data struct {
	// URLhausReference is the host's page on URLhaus.
	URLhausReference string `json:"urlhaus_reference"`
	// FirstSeen is when URLhaus first saw a URL on the host.
	FirstSeen time.Time `json:"first_seen"`
	// URLCount is the number of URLs URLhaus knows on the host.
	URLCount int `json:"url_count"`
	// Blacklists holds the host's status on other blocklists.
	Blacklists Blacklists `json:"blacklists"`
	// URLs are the malware URLs on the host, sorted by URLhaus ID.
	URLs []URL `json:"urls"`
}

// URL is what a URLhaus observation stores about one malware URL.
type URL struct {
	// ID is URLhaus's identifier for the URL.
	ID string `json:"id"`
	// URL is the malware URL. It's stored, never fetched.
	URL string `json:"url"`
	// Status is "online", "offline" or "unknown".
	Status string `json:"status"`
	// DateAdded is when the URL was added; zero, and left out, if URLhaus gave no valid date.
	DateAdded time.Time `json:"date_added,omitzero"`
	// Threat is the kind of threat, such as "malware_download".
	Threat string `json:"threat"`
	// Tags are the reporter's tags, sorted.
	Tags []string `json:"tags"`
}

// Lookup returns URLhaus's report on address, or no reports if URLhaus doesn't know it.
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	// The host lookup is a read-only query sent as a form POST.
	form := url.Values{}
	form.Set("host", address.String())

	header := http.Header{}
	header.Set("Accept", "application/json")
	header.Set("Content-Type", "application/x-www-form-urlencoded")
	header.Set("Auth-Key", string(enricher.apiKey))

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodPost,
		URL:    enricher.hostURL,
		Header: header,
		Body:   []byte(form.Encode()),
	}, MAX_RESPONSE_BYTES)
	if nil != err {
		return nil, fmt.Errorf("querying URLhaus: %w", err)
	}

	return newReports(body)
}

// newReports decodes a URLhaus host response into its report, or no reports if URLhaus doesn't
// know the host. It fails if the query itself failed.
func newReports(body []byte) ([]aggregator.Report, error) {
	var decoded response
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding URLhaus response: %w", err)
	}

	// URLhaus can report a failed query in a 200 response, so its status is mapped to the same
	// kinds of failure as HTTP statuses. Any other status, such as "invalid_host", is about
	// this host alone.
	switch decoded.QueryStatus {
	case NO_RESULTS_STATUS:
		return nil, nil
	case OK_STATUS:
	case UNKNOWN_AUTH_KEY_STATUS:
		return nil, fmt.Errorf("URLhaus query failed with status %q: %w", decoded.QueryStatus, aggregator.ErrUnauthorised)
	default:
		return nil, fmt.Errorf("URLhaus query failed with status %q: %w", decoded.QueryStatus, aggregator.ErrRejected)
	}

	data, err := newData(decoded)
	if nil != err {
		return nil, err
	}

	return []aggregator.Report{aggregator.NewReport("", nil, data)}, nil
}

// newData keeps the stored parts of a host response, with the URLs sorted so a reordered
// response isn't stored as a change. A URL's date that URLhaus wrote in another format is left
// out rather than failing the lookup, because it's only context.
func newData(decoded response) (Data, error) {
	firstSeen, err := time.Parse(TIME_LAYOUT, decoded.FirstSeen)
	if nil != err {
		return Data{}, fmt.Errorf("parsing firstseen %q: %w", decoded.FirstSeen, err)
	}

	urlCount, err := strconv.Atoi(decoded.URLCount)
	if nil != err {
		return Data{}, fmt.Errorf("parsing url_count %q: %w", decoded.URLCount, err)
	}

	urls := make([]URL, 0, len(decoded.URLs))

	for _, hosted := range decoded.URLs {
		// The blank identifier _ discards the parse error: an unparsable date stays zero.
		dateAdded, _ := time.Parse(TIME_LAYOUT, hosted.DateAdded)

		urls = append(urls, URL{
			ID:        hosted.ID,
			URL:       hosted.URL,
			Status:    hosted.URLStatus,
			DateAdded: dateAdded.UTC(),
			Threat:    hosted.Threat,
			Tags:      aggregator.SortedUnique(hosted.Tags),
		})
	}

	// IDs are numbers written as strings, so they're compared as numbers where they are.
	slices.SortFunc(urls, func(first, second URL) int {
		return cmp.Or(cmp.Compare(len(first.ID), len(second.ID)), cmp.Compare(first.ID, second.ID))
	})

	return Data{
		URLhausReference: decoded.URLhausReference,
		FirstSeen:        firstSeen.UTC(),
		URLCount:         urlCount,
		Blacklists:       decoded.Blacklists,
		URLs:             urls,
	}, nil
}
