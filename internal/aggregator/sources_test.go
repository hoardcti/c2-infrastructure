package aggregator

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// REPOSITORY_SOURCES_PATH is the repository's own sources file, relative to this package.
const REPOSITORY_SOURCES_PATH = "../../sources.json"

// TestLoadSources checks that every group and field of the aggregator section is read, and
// that other sections and unknown fields are ignored.
func TestLoadSources(test *testing.T) {
	test.Parallel()

	path := filepath.Join(test.TempDir(), "sources.json")
	content := `{
		"aggregator": {
			"git": [{"name": "g", "enabled": true, "url": "u", "url_raw": "r/", "file_format": "YYYY.csv", "type": "csv"}],
			"json": [{"name": "j", "url": "ju"}],
			"api": [{"name": "a", "enabled": true, "url": "au", "query": {"query": "taginfo", "tag": "c2", "days": 1, "limit": 10}}]
		},
		"tracker": {"censys": []}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); nil != err {
		test.Fatalf("writing sources file: %v", err)
	}

	got, err := LoadSources(path)
	if nil != err {
		test.Fatalf("LoadSources(%q) error = %v, want nil", path, err)
	}

	want := Sources{
		Git:  []Source{{Name: "g", Enabled: true, URL: "u", URLRaw: "r/", FileFormat: "YYYY.csv"}},
		JSON: []Source{{Name: "j", URL: "ju"}},
		API:  []Source{{Name: "a", Enabled: true, URL: "au", Query: APIQuery{Query: "taginfo", Tag: "c2", Days: 1, Limit: 10}}},
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(Source{})); "" != diff {
		test.Errorf("LoadSources(%q) mismatch (-want +got):\n%s", path, diff)
	}
}

// TestLoadSourcesErrors checks that a missing or malformed sources file is reported.
func TestLoadSourcesErrors(test *testing.T) {
	test.Parallel()

	directory := test.TempDir()
	malformedPath := filepath.Join(directory, "malformed.json")
	if err := os.WriteFile(malformedPath, []byte("{"), 0o600); nil != err {
		test.Fatalf("writing malformed sources file: %v", err)
	}

	for _, path := range []string{filepath.Join(directory, "missing.json"), malformedPath} {
		if _, err := LoadSources(path); nil == err {
			test.Errorf("LoadSources(%q) error = nil, want error", path)
		}
	}
}

// TestLoadSourcesRepositoryFile checks that the repository's own sources file is valid, and
// that exactly the sources that were running before the enabled field existed are enabled.
func TestLoadSourcesRepositoryFile(test *testing.T) {
	test.Parallel()

	sources, err := LoadSources(REPOSITORY_SOURCES_PATH)
	if nil != err {
		test.Fatalf("LoadSources(%q) error = %v, want nil", REPOSITORY_SOURCES_PATH, err)
	}

	var enabledNames []string
	for _, source := range sources.enabled() {
		enabledNames = append(enabledNames, source.Name)
	}

	if diff := cmp.Diff([]string{THREATFOX_SOURCE_NAME}, enabledNames); "" != diff {
		test.Errorf("enabled sources mismatch (-want +got):\n%s", diff)
	}

	// Every source, enabled or not, must pass the checks New makes.
	allEnabled := Sources{
		Git:  enableAll(sources.Git),
		JSON: enableAll(sources.JSON),
		CSV:  enableAll(sources.CSV),
		API:  enableAll(sources.API),
	}
	if _, err := New(allEnabled, newTestStore(test), &http.Client{}, WithAbusechAPIKey("key")); nil != err {
		test.Errorf("New() with every repository source enabled error = %v, want nil", err)
	}
}

// enableAll returns copies of sources with every source enabled.
func enableAll(sources []Source) []Source {
	enabledSources := make([]Source, 0, len(sources))
	for _, source := range sources {
		source.Enabled = true
		enabledSources = append(enabledSources, source)
	}

	return enabledSources
}

// TestSourcesEnabled checks that only enabled sources are returned, in processing order and
// labelled with their group.
func TestSourcesEnabled(test *testing.T) {
	test.Parallel()

	sources := Sources{
		Git:  []Source{{Name: "git", Enabled: true}, {Name: "git-disabled"}},
		JSON: []Source{{Name: "json", Enabled: true}},
		CSV:  []Source{{Name: "csv", Enabled: true}},
		API:  []Source{{Name: "api-disabled"}, {Name: "api", Enabled: true}},
	}

	want := []Source{
		{Name: "git", Enabled: true, kind: SOURCE_KIND_GIT},
		{Name: "json", Enabled: true, kind: SOURCE_KIND_JSON},
		{Name: "csv", Enabled: true, kind: SOURCE_KIND_CSV},
		{Name: "api", Enabled: true, kind: SOURCE_KIND_API},
	}
	if diff := cmp.Diff(want, sources.enabled(), cmp.AllowUnexported(Source{})); "" != diff {
		test.Errorf("enabled() mismatch (-want +got):\n%s", diff)
	}

	if "" != sources.Git[0].kind {
		test.Error("enabled() labelled the original sources")
	}
}
