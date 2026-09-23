package aggregator

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/doodad-labs/command-server-watch/internal/aggregator/extractors"
)

const criminalIPBody = "IP,flag,port,score,country,scanTime\n1.2.3.4,Cobalt Strike,443,Critical,US,2026-05-19\n"

// newTestAggregator returns an Aggregator writing to a temp dir with a fixed
// clock, plus the buffer its logs are written to.
func newTestAggregator(t *testing.T) (*Aggregator, *bytes.Buffer) {
	t.Helper()

	var logs bytes.Buffer
	a := New(t.TempDir())
	a.Logger = log.New(&logs, "", 0)
	a.Now = func() time.Time { return time.Date(2026, 5, 9, 12, 0, 0, 0, time.UTC) }

	return a, &logs
}

// serve starts a server that replies to every request with status and body,
// counting the requests it receives and recording the last path.
func serve(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32, *atomic.Value) {
	t.Helper()

	var hits atomic.Int32
	var path atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		path.Store(r.URL.Path)
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	return srv, &hits, &path
}

func ipv4File(a *Aggregator, octets ...string) string {
	last := len(octets) - 1
	elems := append([]string{a.Store.Dir, "ipv4"}, octets[:last]...)

	return filepath.Join(append(elems, octets[last]+".json")...)
}

func assertExists(t *testing.T, path string, want bool) {
	t.Helper()

	_, err := os.Stat(path)
	if got := nil == err; want != got {
		t.Errorf("%s exists = %v, want %v", path, got, want)
	}
}

func TestLoadSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	content := `{
		"aggregator": {
			"git": [{"name": "g", "url": "u", "url_raw": "r/", "file_format": "YYYY.csv", "type": "csv", "metadata": {"cron": "* * * * *"}}],
			"json": [{"name": "j", "url": "ju"}],
			"api": [{"name": "a", "url": "au", "query": {"limit": 10}}]
		},
		"tracker": {"shodan": []}
	}`
	if err := os.WriteFile(path, []byte(content), 0o644); nil != err {
		t.Fatal(err)
	}

	sources, err := LoadSources(path)
	if nil != err {
		t.Fatal(err)
	}

	if 1 != len(sources.Git) || "r/" != sources.Git[0].URLRaw || "YYYY.csv" != sources.Git[0].FileFormat || "* * * * *" != sources.Git[0].Metadata["cron"] {
		t.Errorf("git sources = %+v", sources.Git)
	}
	if 1 != len(sources.JSON) || "ju" != sources.JSON[0].URL {
		t.Errorf("json sources = %+v", sources.JSON)
	}
	if 0 != len(sources.CSV) {
		t.Errorf("csv sources = %+v, want none", sources.CSV)
	}
	if 1 != len(sources.API) || float64(10) != sources.API[0].Query["limit"] {
		t.Errorf("api sources = %+v", sources.API)
	}
}

func TestLoadSourcesRepoConfig(t *testing.T) {
	sources, err := LoadSources(filepath.Join("..", "..", DefaultSourcesFile))
	if nil != err {
		t.Fatal(err)
	}

	if 0 == len(sources.Git) || 0 == len(sources.JSON) || 0 == len(sources.CSV) || 0 == len(sources.API) {
		t.Errorf("repo sources.json is missing a source group: %+v", sources)
	}
}

func TestLoadSourcesErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := LoadSources(filepath.Join(dir, "missing.json")); nil == err {
		t.Error("LoadSources(missing) error = nil, want error")
	}

	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o644); nil != err {
		t.Fatal(err)
	}
	if _, err := LoadSources(bad); nil == err {
		t.Error("LoadSources(bad json) error = nil, want error")
	}
}

func TestNew(t *testing.T) {
	a := New("dir")

	if nil == a.Client || nil == a.Logger || nil == a.Now || "dir" != a.Store.Dir {
		t.Errorf("New() = %+v, want all fields set", a)
	}
}

func TestBuildURL(t *testing.T) {
	a, _ := newTestAggregator(t)

	tests := []struct {
		format string
		want   string
	}{
		{"YYYY-MM-DD.csv", "https://raw.example/2026-05-09.csv"},
		{"DD.MM.YYYY", "https://raw.example/09.05.2026"},
		{"static.csv", "https://raw.example/static.csv"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got := a.buildURL(Source{URLRaw: "https://raw.example/", FileFormat: tt.format})
			if tt.want != got {
				t.Errorf("buildURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProcessGitSource(t *testing.T) {
	a, _ := newTestAggregator(t)
	srv, _, path := serve(t, http.StatusOK, criminalIPBody)

	a.processGitSource(context.Background(), Source{Name: "criminalip", URLRaw: srv.URL + "/feed/", FileFormat: "YYYY-MM-DD.csv"})

	if got := path.Load(); "/feed/2026-05-09.csv" != got {
		t.Errorf("requested path = %v, want /feed/2026-05-09.csv", got)
	}
	assertExists(t, ipv4File(a, "1", "2", "3", "4"), true)
}

func TestProcessFeedSource(t *testing.T) {
	srv, _, _ := serve(t, http.StatusOK, criminalIPBody)

	a, logs := newTestAggregator(t)
	a.processFeedSource(context.Background(), Source{Name: "criminalip"}, srv.URL)

	assertExists(t, ipv4File(a, "1", "2", "3", "4"), true)
	if 0 != logs.Len() {
		t.Errorf("unexpected logs: %s", logs)
	}
}

func TestProcessFeedSourceFailures(t *testing.T) {
	ok, _, _ := serve(t, http.StatusOK, criminalIPBody)
	notFound, _, _ := serve(t, http.StatusNotFound, criminalIPBody)
	garbage, _, _ := serve(t, http.StatusOK, "header\nnot,enough\n")

	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	tests := []struct {
		name    string
		source  string
		url     string
		wantLog string
	}{
		{"http error", "criminalip", notFound.URL, "(HTTP 404)"},
		{"unreachable", "criminalip", closedURL, "Failed to fetch criminalip"},
		{"bad url", "criminalip", "://bad", "Failed to fetch criminalip"},
		{"unknown extractor", "nope", ok.URL, "No extractor registered for source: nope"},
		{"extractor error", "criminalip", garbage.URL, "Failed to extract criminalip"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, logs := newTestAggregator(t)
			a.processFeedSource(context.Background(), Source{Name: tt.source}, tt.url)

			if false == strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("logs = %q, want to contain %q", logs, tt.wantLog)
			}
			assertExists(t, ipv4File(a, "1", "2", "3", "4"), false)
		})
	}
}

func TestProcessAPISource(t *testing.T) {
	srv, _, _ := serve(t, http.StatusOK, `{"query_status": "ok", "data": [
		{"ioc": "5.6.7.8:443", "ioc_type": "ip:port", "malware_printable": "Sliver", "first_seen": "2026-05-09 00:00:00 UTC"}
	]}`)

	a, logs := newTestAggregator(t)
	a.processAPISource(context.Background(), Source{
		Name:  "threatfox",
		URL:   srv.URL,
		Query: map[string]any{"query": "taginfo", "limit": float64(1)},
	})

	assertExists(t, ipv4File(a, "5", "6", "7", "8"), true)
	if strings.Contains(logs.String(), "Failed") {
		t.Errorf("unexpected failure logs: %s", logs)
	}
}

func TestProcessAPISourceFailures(t *testing.T) {
	a, logs := newTestAggregator(t)

	a.processAPISource(context.Background(), Source{Name: "nope"})
	if false == strings.Contains(logs.String(), "No extractor registered for source: nope") {
		t.Errorf("logs = %q, want missing extractor warning", logs)
	}

	logs.Reset()

	// A nil query is passed as empty, which threatfox rejects
	a.processAPISource(context.Background(), Source{Name: "threatfox", URL: "http://127.0.0.1:0"})
	if false == strings.Contains(logs.String(), "Failed to extract threatfox") {
		t.Errorf("logs = %q, want extraction failure", logs)
	}
}

func TestRunOnlyProcessesAPISources(t *testing.T) {
	feed, feedHits, _ := serve(t, http.StatusOK, criminalIPBody)
	api, apiHits, _ := serve(t, http.StatusOK, `{"query_status": "ok", "data": []}`)

	a, _ := newTestAggregator(t)
	a.Run(context.Background(), Sources{
		Git:  []Source{{Name: "criminalip", URLRaw: feed.URL + "/", FileFormat: "x.csv"}},
		JSON: []Source{{Name: "feodotracker", URL: feed.URL}},
		CSV:  []Source{{Name: "viribacktracker", URL: feed.URL}},
		API:  []Source{{Name: "threatfox", URL: api.URL, Query: map[string]any{"query": "taginfo", "limit": float64(1)}}},
	})

	if 0 != feedHits.Load() {
		t.Errorf("feed sources were fetched %d times, want 0 (disabled)", feedHits.Load())
	}
	if 1 != apiHits.Load() {
		t.Errorf("api source was fetched %d times, want 1", apiHits.Load())
	}
}

func TestSaveLogsFailures(t *testing.T) {
	a, logs := newTestAggregator(t)

	// Block the ipv4 directory with a file so MkdirAll fails
	if err := os.WriteFile(filepath.Join(a.Store.Dir, "ipv4"), nil, 0o644); nil != err {
		t.Fatal(err)
	}

	payloads, err := extractors.CriminalIP(criminalIPBody)
	if nil != err {
		t.Fatal(err)
	}
	a.save(payloads)

	if false == strings.Contains(logs.String(), "Failed to save payload for 1.2.3.4") {
		t.Errorf("logs = %q, want save failure", logs)
	}
}
