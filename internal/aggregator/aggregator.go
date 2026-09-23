// Package aggregator fetches C2 feeds listed in sources.json and stores
// the extracted IPs on disk.
package aggregator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/doodad-labs/command-server-watch/internal/aggregator/extractors"
	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// DefaultSourcesFile is the path to the sources config, relative to the working directory.
const DefaultSourcesFile = "sources.json"

// Source is a single feed definition from sources.json.
type Source struct {
	Name       string         `json:"name"`
	URL        string         `json:"url"`
	URLRaw     string         `json:"url_raw,omitempty"`
	FileFormat string         `json:"file_format,omitempty"`
	Type       string         `json:"type,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	Query      map[string]any `json:"query,omitempty"`
}

// Sources is the "aggregator" section of sources.json, grouped by how each
// feed is fetched.
type Sources struct {
	Git  []Source `json:"git"`
	JSON []Source `json:"json"`
	CSV  []Source `json:"csv"`
	API  []Source `json:"api"`
}

// LoadSources reads the aggregator section of the sources config at path.
func LoadSources(path string) (Sources, error) {
	data, err := os.ReadFile(path)
	if nil != err {
		return Sources{}, err
	}

	var config struct {
		Aggregator Sources `json:"aggregator"`
	}
	if err := json.Unmarshal(data, &config); nil != err {
		return Sources{}, fmt.Errorf("decode %s: %w", path, err)
	}

	return config.Aggregator, nil
}

// Aggregator fetches feeds and saves their payloads to a Store.
type Aggregator struct {
	Client *http.Client
	Store  *Store
	Logger *log.Logger
	Now    func() time.Time
}

// New returns an Aggregator that writes payloads under outputDir.
func New(outputDir string) *Aggregator {
	return &Aggregator{
		Client: &http.Client{Timeout: 2 * time.Minute},
		Store:  &Store{Dir: outputDir},
		Logger: log.Default(),
		Now:    time.Now,
	}
}

// Run processes each configured feed.
func (a *Aggregator) Run(ctx context.Context, sources Sources) {
	// Only API sources are enabled for now
	// for _, source := range sources.Git {
	// 	a.processGitSource(ctx, source)
	// }

	// for _, source := range sources.JSON {
	// 	a.processFeedSource(ctx, source, source.URL)
	// }

	// for _, source := range sources.CSV {
	// 	a.processFeedSource(ctx, source, source.URL)
	// }

	for _, source := range sources.API {
		a.processAPISource(ctx, source)
	}
}

// buildURL resolves the full URL for today's feed file from a source definition.
//
// The file_format field supports YYYY, MM, and DD tokens which are replaced
// with today's date values, e.g. "YYYY-MM-DD.csv" → "2026-05-19.csv".
func (a *Aggregator) buildURL(source Source) string {
	today := a.Now()

	filename := strings.NewReplacer(
		"YYYY", today.Format("2006"),
		"MM", today.Format("01"),
		"DD", today.Format("02"),
	).Replace(source.FileFormat)

	return source.URLRaw + filename
}

// processGitSource fetches and ingests a single git-hosted feed source,
// whose file name is derived from today's date.
func (a *Aggregator) processGitSource(ctx context.Context, source Source) {
	a.processFeedSource(ctx, source, a.buildURL(source))
}

// processFeedSource fetches url and ingests its body.
//
// Looks up the registered extractor for the source by name, parses the
// response body into payloads, and persists each one via SavePayload.
func (a *Aggregator) processFeedSource(ctx context.Context, source Source, url string) {
	body, status, err := a.fetch(ctx, url)
	if nil != err {
		a.Logger.Printf("Failed to fetch %s from %s: %v", source.Name, url, err)
		return
	}

	// Bail early if the feed returned an error
	if http.StatusOK != status {
		a.Logger.Printf("Failed to fetch %s from %s (HTTP %d)", source.Name, url, status)
		return
	}

	extractor := extractors.Registry[source.Name]

	// Warn and skip if no extractor has been registered for this source name
	if nil == extractor {
		a.Logger.Printf("No extractor registered for source: %s", source.Name)
		return
	}

	payloads, err := extractor(body)
	if nil != err {
		a.Logger.Printf("Failed to extract %s: %v", source.Name, err)
		return
	}

	a.save(payloads)
}

// processAPISource runs the registered API extractor for a source, which
// performs its own requests, and persists the payloads it returns.
func (a *Aggregator) processAPISource(ctx context.Context, source Source) {
	extractor := extractors.APIRegistry[source.Name]

	// Warn and skip if no extractor has been registered for this source name
	if nil == extractor {
		a.Logger.Printf("No extractor registered for source: %s", source.Name)
		return
	}

	query := source.Query
	if nil == query {
		query = map[string]any{}
	}

	payloads, err := extractor(ctx, a.Client, source.URL, query)
	if nil != err {
		a.Logger.Printf("Failed to extract %s: %v", source.Name, err)
		return
	}

	a.save(payloads)
}

// fetch GETs url and returns its body and status code.
func (a *Aggregator) fetch(ctx context.Context, url string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if nil != err {
		return "", 0, err
	}

	resp, err := a.Client.Do(req)
	if nil != err {
		return "", 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if nil != err {
		return "", resp.StatusCode, err
	}

	return string(body), resp.StatusCode, nil
}

// save persists each payload, logging rather than aborting on failure.
func (a *Aggregator) save(payloads []payload.Payload) {
	for _, p := range payloads {
		if err := a.Store.SavePayload(p); nil != err {
			a.Logger.Printf("Failed to save payload for %s: %v", p.IP, err)
		}
	}
}
