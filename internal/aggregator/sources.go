package aggregator

import (
	"encoding/json/v2"
	"fmt"
	"os"
)

// Source kinds: how a source is fetched. The values are the group names used in the
// "aggregator" section of sources.json.
const (
	// SOURCE_KIND_GIT is a feed published as one dated file per day in a Git repository.
	SOURCE_KIND_GIT sourceKind = "git"
	// SOURCE_KIND_JSON is a JSON feed downloaded from a fixed URL.
	SOURCE_KIND_JSON sourceKind = "json"
	// SOURCE_KIND_CSV is a CSV feed downloaded from a fixed URL.
	SOURCE_KIND_CSV sourceKind = "csv"
	// SOURCE_KIND_API is an API that is queried with a request body.
	SOURCE_KIND_API sourceKind = "api"
)

// sourceKind says how a source is fetched.
type sourceKind string

// Sources is the "aggregator" section of sources.json, grouped by how each source is fetched.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type Sources struct {
	// Git lists feeds published as dated files in a Git repository.
	Git []Source `json:"git"`
	// JSON lists JSON feeds downloaded from a fixed URL.
	JSON []Source `json:"json"`
	// CSV lists CSV feeds downloaded from a fixed URL.
	CSV []Source `json:"csv"`
	// API lists APIs that are queried with a request body.
	API []Source `json:"api"`
}

// Source is one feed in sources.json. Fields a source's kind doesn't use are left empty.
type Source struct {
	// Name identifies the source and selects its extractor. It's also the "source" of every
	// published result.
	Name string `json:"name"`
	// Enabled says whether the source is processed. It's false when absent, so every source
	// in sources.json states it explicitly.
	Enabled bool `json:"enabled"`
	// URL is where a JSON, CSV or API source is fetched from. For a Git source it's the
	// repository's web page, which is documentation only and never fetched.
	URL string `json:"url"`
	// URLRaw is the base URL of a Git source's raw files.
	URLRaw string `json:"url_raw"`
	// FileFormat is the name of a Git source's daily file, where YYYY, MM and DD stand for
	// today's year, month and day, such as "YYYY-MM-DD.csv".
	FileFormat string `json:"file_format"`
	// Query is the request body sent to an API source.
	Query APIQuery `json:"query"`
	// kind records which group the source was listed in. It's set by Sources.enabled, not
	// read from JSON: encoding/json skips unexported fields.
	kind sourceKind
}

// APIQuery is the JSON request body sent to an API source. Its fields are the ThreatFox API's,
// the only API source so far.
type APIQuery struct {
	// Query is the API operation, such as "taginfo"; required.
	Query string `json:"query"`
	// Tag selects indicators with this tag. omitzero leaves it out of the request when empty.
	Tag string `json:"tag,omitzero"`
	// Days limits results to indicators first seen in this many days.
	Days int `json:"days,omitzero"`
	// Limit is the maximum number of indicators returned; at least 1.
	Limit int `json:"limit"`
}

// LoadSources reads the "aggregator" section of the sources configuration file at path. The
// sources are validated when they're given to New.
func LoadSources(path string) (Sources, error) {
	content, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the -sources flag.
	if nil != err {
		return Sources{}, fmt.Errorf("reading sources file: %w", err)
	}

	// Other sections of the file, such as "tracker", belong to other programs and are ignored.
	var configuration struct {
		// Aggregator is the only section this program reads.
		Aggregator Sources `json:"aggregator"`
	}
	if err := json.Unmarshal(content, &configuration); nil != err {
		return Sources{}, fmt.Errorf("decoding sources file %q: %w", path, err)
	}

	return configuration.Aggregator, nil
}

// enabled returns every enabled source in the order Run processes them, each labelled with the
// group it was listed in.
func (sources Sources) enabled() []Source {
	groups := []struct {
		kind    sourceKind
		sources []Source
	}{
		{kind: SOURCE_KIND_GIT, sources: sources.Git},
		{kind: SOURCE_KIND_JSON, sources: sources.JSON},
		{kind: SOURCE_KIND_CSV, sources: sources.CSV},
		{kind: SOURCE_KIND_API, sources: sources.API},
	}

	var enabledSources []Source

	for _, group := range groups {
		for _, source := range group.sources {
			if !source.Enabled {
				continue
			}

			// source is this iteration's own copy, so labelling it leaves sources unchanged.
			source.kind = group.kind
			enabledSources = append(enabledSources, source)
		}
	}

	return enabledSources
}
