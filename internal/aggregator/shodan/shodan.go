// Package shodan is the Shodan enricher: the services Shodan's scanners found on an address,
// with their software, HTTP titles, TLS certificates and JARM fingerprints, from Shodan's host
// API.
//
// Banner timestamps and raw banner text aren't stored: they change with every scan, so storing
// them would record a "change" every time Shodan rescans an unchanged server.
//
// The free plan answers most host lookups, but refuses the minify option and some hosts with
// 403 "Requires membership or higher to access". Lookups never ask for minify, and a refused
// host is recorded on its address without stopping the source.
//
// It's a package of its own, imported only by the command, because it hides state the rest of
// the program mustn't touch: the Shodan key and Shodan's response types (GO-PKG-004,
// reason 3), like every source.
package shodan

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

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// The Shodan host API.
const (
	// SOURCE_NAME names Shodan in sources.json and in every record.
	SOURCE_NAME = "shodan"
	// MAX_RESPONSE_BYTES bounds a response. Hosts with many services give a few MiB.
	MAX_RESPONSE_BYTES = 16 << 20
)

// Enricher looks addresses up in Shodan. Build one with New.
type Enricher struct {
	// baseURL is the host endpoint; the address is appended to it.
	baseURL *url.URL
	// upstream sends the requests.
	upstream *aggregator.Upstream
	// apiKey is the Shodan API key.
	apiKey aggregator.APIKey
}

// New builds the Shodan enricher from its sources.json entry. apiKey must be set.
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
		return nil, errors.New("the Shodan API key is required")
	}

	return &Enricher{baseURL: endpoint, upstream: upstream, apiKey: apiKey}, nil
}

// host mirrors the parts of a Shodan host response that are stored. Upstream fields that
// aren't stored are left out, and encoding/json ignores them when decoding.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type host struct {
	// Org is the organisation the address is assigned to.
	Org string `json:"org"`
	// ISP is the internet service provider.
	ISP string `json:"isp"`
	// ASN is the autonomous system, such as "AS45090".
	ASN string `json:"asn"`
	// OS is the operating system Shodan detected, or null.
	OS *string `json:"os"`
	// CountryCode is the two-letter country code.
	CountryCode string `json:"country_code"`
	// Hostnames are the address's hostnames.
	Hostnames []string `json:"hostnames"`
	// Domains are the domains of those hostnames.
	Domains []string `json:"domains"`
	// Tags are Shodan's tags for the host, such as "c2".
	Tags []string `json:"tags"`
	// Vulns are the CVE identifiers the host is likely vulnerable to.
	Vulns []string `json:"vulns"`
	// Data holds one banner per service.
	Data []banner `json:"data"`
}

// banner mirrors the stored fields of one Shodan service banner.
type banner struct {
	// Port is the service's port.
	Port uint16 `json:"port"`
	// Transport is "tcp" or "udp".
	Transport string `json:"transport"`
	// Product is the software Shodan identified, such as "Cobalt Strike Beacon".
	Product string `json:"product"`
	// Version is the software's version, if known.
	Version string `json:"version"`
	// Tags are Shodan's tags for the service.
	Tags []string `json:"tags"`
	// HTTP holds HTTP details for web services, or null.
	HTTP *struct {
		// Title is the page title.
		Title string `json:"title"`
	} `json:"http"`
	// SSL holds TLS details for TLS services, or null.
	SSL *struct {
		// JARM is the TLS server fingerprint.
		JARM string `json:"jarm"`
		// Cert is the server's certificate.
		Cert struct {
			// Fingerprint holds the certificate's hashes.
			Fingerprint struct {
				// SHA256 is the certificate's SHA-256 fingerprint.
				SHA256 string `json:"sha256"`
			} `json:"fingerprint"`
			// Subject is the certificate's subject.
			Subject certificateName `json:"subject"`
			// Issuer is the certificate's issuer.
			Issuer certificateName `json:"issuer"`
		} `json:"cert"`
	} `json:"ssl"`
}

// certificateName mirrors the stored parts of a certificate subject or issuer.
type certificateName struct {
	// CommonName is the CN attribute.
	CommonName string `json:"CN"` //nolint:tagliatelle // GO-EXT-002: Shodan's own field name.
	// Organisation is the O attribute.
	Organisation string `json:"O"` //nolint:tagliatelle // GO-EXT-002: Shodan's own field name.
}

// Data is what a Shodan observation stores.
type Data struct {
	// Org is the organisation the address is assigned to.
	Org string `json:"org"`
	// ISP is the internet service provider.
	ISP string `json:"isp"`
	// ASN is the autonomous system, such as "AS45090".
	ASN string `json:"asn"`
	// OS is the operating system Shodan detected, or nil (stored as null).
	OS *string `json:"os"`
	// CountryCode is the two-letter country code.
	CountryCode string `json:"country_code"`
	// Hostnames are the address's hostnames, sorted.
	Hostnames []string `json:"hostnames"`
	// Domains are the domains of those hostnames, sorted.
	Domains []string `json:"domains"`
	// Tags are Shodan's tags for the host, sorted.
	Tags []string `json:"tags"`
	// Vulns are the CVE identifiers the host is likely vulnerable to, sorted.
	Vulns []string `json:"vulns"`
	// Services are the services found, sorted by port and transport.
	Services []Service `json:"services"`
}

// Service is what a Shodan observation stores about one service. Empty fields are left out.
type Service struct {
	// Port is the service's port.
	Port uint16 `json:"port"`
	// Transport is "tcp" or "udp".
	Transport string `json:"transport"`
	// Product is the software Shodan identified, such as "Cobalt Strike Beacon".
	Product string `json:"product,omitzero"`
	// Version is the software's version.
	Version string `json:"version,omitzero"`
	// Tags are Shodan's tags for the service, sorted.
	Tags []string `json:"tags,omitzero"`
	// HTTPTitle is the title of a web service's page.
	HTTPTitle string `json:"http_title,omitzero"`
	// JARM is a TLS service's server fingerprint.
	JARM string `json:"jarm,omitzero"`
	// CertificateSHA256 is the SHA-256 fingerprint of a TLS service's certificate.
	CertificateSHA256 string `json:"certificate_sha256,omitzero"`
	// CertificateSubject is the certificate subject's common name.
	CertificateSubject string `json:"certificate_subject,omitzero"`
	// CertificateOrganisation is the certificate subject's organisation, such as
	// "cobaltstrike" for Cobalt Strike's default certificate.
	CertificateOrganisation string `json:"certificate_organisation,omitzero"`
	// CertificateIssuer is the certificate issuer's common name.
	CertificateIssuer string `json:"certificate_issuer,omitzero"`
}

// Lookup returns Shodan's report on address, or no reports if Shodan has no information about
// it (404 Not Found).
func (enricher *Enricher) Lookup(ctx context.Context, address netip.Addr) ([]aggregator.Report, error) {
	// Shodan only accepts the key as a query parameter. Upstream never shows the query in
	// errors, and the key is registered with it to be removed from response snippets too. The
	// URL is a copy, so the enricher's own is never changed.
	query := url.Values{}
	query.Set("key", string(enricher.apiKey))

	lookupURL := enricher.baseURL.JoinPath(address.String())
	lookupURL.RawQuery = query.Encode()

	header := http.Header{}
	header.Set("Accept", "application/json")

	body, err := enricher.upstream.Fetch(ctx, aggregator.Request{
		Method: http.MethodGet,
		URL:    lookupURL.String(),
		Header: header,
	}, MAX_RESPONSE_BYTES)
	if aggregator.IsNotFound(err) {
		return nil, nil
	}

	// On the free plan Shodan answers most hosts but refuses some with 403 "Requires
	// membership or higher to access" (seen 2026-10-01). That refusal is about this host, not
	// the key, so it's reported as a rejected request: the aggregator records it on the
	// address and carries on, instead of stopping the source as it does for other 403s. The
	// status error isn't wrapped, so the result no longer counts as ErrForbidden; its
	// explanation is kept in the message.
	if statusError, ok := errors.AsType[*aggregator.StatusError](err); ok && http.StatusForbidden == statusError.StatusCode {
		return nil, fmt.Errorf("querying Shodan: %w: the key's plan doesn't include this host: %q", aggregator.ErrRejected, statusError.Snippet)
	}

	if nil != err {
		return nil, fmt.Errorf("querying Shodan: %w", err)
	}

	return newReports(body)
}

// newReports decodes a Shodan host response into its report.
func newReports(body []byte) ([]aggregator.Report, error) {
	var decoded host
	if err := json.Unmarshal(body, &decoded); nil != err {
		return nil, fmt.Errorf("decoding Shodan response: %w", err)
	}

	return []aggregator.Report{aggregator.NewReport("", nil, newData(decoded))}, nil
}

// newData keeps the stored parts of a host, with every list sorted so a reordered response
// isn't stored as a change.
func newData(decoded host) Data {
	services := make([]Service, 0, len(decoded.Data))

	for _, found := range decoded.Data {
		service := Service{
			Port:      found.Port,
			Transport: found.Transport,
			Product:   found.Product,
			Version:   found.Version,
			Tags:      aggregator.SortedUnique(found.Tags),
		}

		if nil != found.HTTP {
			service.HTTPTitle = found.HTTP.Title
		}

		if nil != found.SSL {
			service.JARM = found.SSL.JARM
			service.CertificateSHA256 = found.SSL.Cert.Fingerprint.SHA256
			service.CertificateSubject = found.SSL.Cert.Subject.CommonName
			service.CertificateOrganisation = found.SSL.Cert.Subject.Organisation
			service.CertificateIssuer = found.SSL.Cert.Issuer.CommonName
		}

		services = append(services, service)
	}

	// cmp.Or returns its first non-zero argument, so the transport only breaks ties of port.
	slices.SortFunc(services, func(first, second Service) int {
		return cmp.Or(cmp.Compare(first.Port, second.Port), cmp.Compare(first.Transport, second.Transport))
	})

	return Data{
		Org:         decoded.Org,
		ISP:         decoded.ISP,
		ASN:         decoded.ASN,
		OS:          decoded.OS,
		CountryCode: decoded.CountryCode,
		Hostnames:   aggregator.SortedUnique(decoded.Hostnames),
		Domains:     aggregator.SortedUnique(decoded.Domains),
		Tags:        aggregator.SortedUnique(decoded.Tags),
		Vulns:       aggregator.SortedUnique(decoded.Vulns),
		Services:    services,
	}
}
