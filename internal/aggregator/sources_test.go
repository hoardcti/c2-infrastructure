package aggregator

import (
	"encoding/json/jsontext"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestLoadConfiguration checks that the aggregator section is read and other sections, such as
// the tracker's, are ignored.
func TestLoadConfiguration(test *testing.T) {
	test.Parallel()

	path := writeConfigurationFile(test, `{
		"aggregator": {
			"feeds": [{"name": "threatfox", "enabled": true, "url": "https://example.com/", "requests_per_minute": 10, "options": {"query": "taginfo"}}],
			"enrichers": [{"name": "ipinfo", "enabled": false, "url": "https://example.com/", "requests_per_minute": 60, "max_lookups": 5, "refresh_after_hours": 24, "max_minutes_per_run": 2}]
		},
		"tracker": {"censys": [{"name": "anything"}]}
	}`)

	configuration, err := LoadConfiguration(path)
	if nil != err {
		test.Fatalf("LoadConfiguration() error = %v, want nil", err)
	}

	want := Configuration{
		Feeds: []SourceConfig{{
			Name: "threatfox", Enabled: true, URL: "https://example.com/", RequestsPerMinute: 10,
			Options: jsontext.Value(`{"query": "taginfo"}`),
		}},
		Enrichers: []SourceConfig{{
			Name: "ipinfo", URL: "https://example.com/", RequestsPerMinute: 60,
			MaxLookups: 5, RefreshAfterHours: 24, MaxMinutesPerRun: 2,
		}},
	}
	if diff := cmp.Diff(want, configuration, recordComparison); "" != diff {
		test.Errorf("LoadConfiguration() mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadConfigurationErrors checks the files LoadConfiguration refuses.
func TestLoadConfigurationErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		content string
		// wantErr is part of the error LoadConfiguration must return.
		wantErr string
	}{
		{name: "not JSON", content: `{`, wantErr: "decoding sources file"},
		{name: "no aggregator section", content: `{"tracker": {}}`, wantErr: "no aggregator section"},
		// A mistyped setting must fail at start-up, not be silently ignored.
		{name: "unknown setting", content: `{"aggregator": {"feeds": [{"name": "x", "enabeld": true}]}}`, wantErr: "enabeld"},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			_, err := LoadConfiguration(writeConfigurationFile(subtest, testCase.content))
			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("LoadConfiguration(%s) error = %v, want one containing %q", testCase.content, err, testCase.wantErr)
			}
		})
	}

	if _, err := LoadConfiguration(filepath.Join(test.TempDir(), "missing.json")); nil == err {
		test.Error("LoadConfiguration(missing file) error = nil, want error")
	}
}

// TestRepositoryConfiguration checks the repository's own sources.json: it loads, and every
// enricher has a valid schedule whose daily lookups stay within its free quota where one is
// documented.
func TestRepositoryConfiguration(test *testing.T) {
	test.Parallel()

	configuration, err := LoadConfiguration(filepath.Join("..", "..", "sources.json"))
	if nil != err {
		test.Fatalf("LoadConfiguration(sources.json) error = %v, want nil", err)
	}

	// Daily quotas of the free tiers, from KEY.md. The workflow runs every hour.
	dailyQuotas := map[string]int{"virustotal": 500, "abuseipdb": 1000}

	for _, enricher := range configuration.Enrichers {
		if _, err := enricher.Schedule(); nil != err {
			test.Errorf("enricher %q schedule error = %v, want nil", enricher.Name, err)
		}

		if quota, ok := dailyQuotas[enricher.Name]; ok && 24*enricher.MaxLookups > quota {
			test.Errorf("enricher %q looks up %d addresses a day, over its quota of %d", enricher.Name, 24*enricher.MaxLookups, quota)
		}
	}
}

// TestSourceConfigSchedule checks that a complete schedule is converted, and an incomplete one
// refused.
func TestSourceConfigSchedule(test *testing.T) {
	test.Parallel()

	schedule, err := SourceConfig{MaxLookups: 5, RefreshAfterHours: 24, MaxMinutesPerRun: 3}.Schedule()
	want := Schedule{MaxLookups: 5, RefreshAfter: 24 * time.Hour, MaxDuration: 3 * time.Minute}

	if nil != err || want != schedule {
		test.Errorf("Schedule() = (%+v, %v), want %+v", schedule, err, want)
	}

	for _, config := range []SourceConfig{
		{RefreshAfterHours: 1, MaxMinutesPerRun: 1},
		{MaxLookups: 1, MaxMinutesPerRun: 1},
		{MaxLookups: 1, RefreshAfterHours: 1},
	} {
		if _, err := config.Schedule(); nil == err {
			test.Errorf("Schedule() of %+v error = nil, want error", config)
		}
	}
}

// TestDecodeOptions checks that options are decoded strictly, and that missing options leave
// the defaults alone.
func TestDecodeOptions(test *testing.T) {
	test.Parallel()

	// options is a source's own settings type.
	type options struct {
		// Days is a setting with a default.
		Days int `json:"days"`
	}

	decoded := options{Days: 7}
	if err := DecodeOptions(nil, &decoded); nil != err || 7 != decoded.Days {
		test.Errorf("DecodeOptions(nil) = (%+v, %v), want the default kept", decoded, err)
	}

	if err := DecodeOptions(jsontext.Value(`{"days": 1}`), &decoded); nil != err || 1 != decoded.Days {
		test.Errorf("DecodeOptions(days 1) = (%+v, %v), want days 1", decoded, err)
	}

	if err := DecodeOptions(jsontext.Value(`{"dayz": 1}`), &decoded); nil == err {
		test.Error("DecodeOptions(unknown field) error = nil, want error")
	}
}

// TestParseUpstreamURL checks that only absolute https URLs are accepted.
func TestParseUpstreamURL(test *testing.T) {
	test.Parallel()

	if parsed, err := ParseUpstreamURL("https://example.com/api/"); nil != err || "/api/" != parsed.Path {
		test.Errorf("ParseUpstreamURL(https) = (%v, %v), want the parsed URL", parsed, err)
	}

	for _, rawURL := range []string{"http://example.com/", "/relative", "", "https://[::1"} {
		if _, err := ParseUpstreamURL(rawURL); nil == err {
			test.Errorf("ParseUpstreamURL(%q) error = nil, want error", rawURL)
		}
	}
}

// writeConfigurationFile writes content to a sources file in a temporary directory and returns
// its path.
func writeConfigurationFile(testingContext testing.TB, content string) string {
	testingContext.Helper()

	path := filepath.Join(testingContext.TempDir(), "sources.json")
	if err := os.WriteFile(path, []byte(content), 0o600); nil != err {
		testingContext.Fatalf("writing sources file: %v", err)
	}

	return path
}
