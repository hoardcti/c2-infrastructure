package aggregator

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"
)

// Configuration is the "aggregator" section of sources.json: every source, enabled or not, in
// the order the run processes them.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key.
type Configuration struct {
	// Feeds lists sources that discover C2 servers. They run first, so enrichers also see the
	// addresses they add.
	Feeds []SourceConfig `json:"feeds"`
	// Enrichers lists sources that look up addresses already in the dataset.
	Enrichers []SourceConfig `json:"enrichers"`
}

// SourceConfig is one source in sources.json. The command passes it to the source's package,
// which checks the fields it uses.
type SourceConfig struct {
	// Name identifies the source and selects its package. It's also the key of the source's
	// history in every record.
	Name string `json:"name"`
	// Enabled says whether the source is processed. It's false when absent, so every source
	// states it explicitly.
	Enabled bool `json:"enabled"`
	// URL is the upstream endpoint or base URL. It must be absolute https.
	URL string `json:"url"`
	// RequestsPerMinute caps how fast the source's requests are sent, retries included.
	RequestsPerMinute int `json:"requests_per_minute"`
	// MaxLookups caps how many addresses an enricher looks up in one run, so a run stays
	// within the upstream's daily quota.
	MaxLookups int `json:"max_lookups,omitzero"`
	// RefreshAfterHours is how long an enricher waits before looking an address up again.
	RefreshAfterHours int `json:"refresh_after_hours,omitzero"`
	// MaxMinutesPerRun caps how long an enricher may spend in one run, so a slow upstream
	// can't hold up the run.
	MaxMinutesPerRun int `json:"max_minutes_per_run,omitzero"`
	// Options holds settings only one source uses, such as ThreatFox's query. Each source
	// package decodes it with DecodeOptions.
	Options jsontext.Value `json:"options,omitzero"`
}

// LoadConfiguration reads the "aggregator" section of the sources file at path. Unknown fields
// in that section are refused, so a mistyped setting is caught at start-up. Each source's own
// settings are checked when its package builds it.
func LoadConfiguration(path string) (Configuration, error) {
	content, err := os.ReadFile(path) //nolint:gosec // G304: path comes from the -sources flag.
	if nil != err {
		return Configuration{}, fmt.Errorf("reading sources file: %w", err)
	}

	// Other sections of the file, such as "tracker", belong to other programs, so only the
	// aggregator section is decoded strictly.
	var file struct {
		// Aggregator is the only section this program reads.
		Aggregator jsontext.Value `json:"aggregator"`
	}
	if err := json.Unmarshal(content, &file); nil != err {
		return Configuration{}, fmt.Errorf("decoding sources file %q: %w", path, err)
	}

	if 0 == len(file.Aggregator) {
		return Configuration{}, fmt.Errorf("sources file %q has no aggregator section", path)
	}

	var configuration Configuration
	if err := json.Unmarshal(file.Aggregator, &configuration, json.RejectUnknownMembers(true)); nil != err {
		return Configuration{}, fmt.Errorf("decoding aggregator section of %q: %w", path, err)
	}

	return configuration, nil
}

// Schedule returns how an enricher spreads its lookups over runs. max_lookups,
// refresh_after_hours and max_minutes_per_run must all be at least 1.
func (config SourceConfig) Schedule() (Schedule, error) {
	isPositive := config.MaxLookups >= 1 && config.RefreshAfterHours >= 1 && config.MaxMinutesPerRun >= 1
	if !isPositive {
		return Schedule{}, errors.New("max_lookups, refresh_after_hours and max_minutes_per_run must be at least 1")
	}

	return Schedule{
		MaxLookups:   config.MaxLookups,
		RefreshAfter: time.Duration(config.RefreshAfterHours) * time.Hour,
		MaxDuration:  time.Duration(config.MaxMinutesPerRun) * time.Minute,
	}, nil
}

// DecodeOptions decodes a source's options into target, refusing unknown fields. Missing
// options leave target unchanged.
func DecodeOptions(options jsontext.Value, target any) error {
	if 0 == len(options) {
		return nil
	}

	if err := json.Unmarshal(options, target, json.RejectUnknownMembers(true)); nil != err {
		return fmt.Errorf("decoding options: %w", err)
	}

	return nil
}

// ParseUpstreamURL parses rawURL and checks that it's an absolute https URL. Upstream data
// travels only over TLS, so nobody on the network path can tamper with the intelligence we
// store. Sources keep the parsed URL and derive request URLs from it with JoinPath and
// RawQuery, which can't fail.
func ParseUpstreamURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if nil != err {
		return nil, fmt.Errorf("parsing URL: %w", err)
	}

	isAbsoluteHTTPS := "https" == parsedURL.Scheme && "" != parsedURL.Host
	if !isAbsoluteHTTPS {
		return nil, fmt.Errorf("URL %q isn't an absolute https URL", rawURL)
	}

	return parsedURL, nil
}
