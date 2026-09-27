package aggregator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestAPIKeyRedacts checks that an API key never appears when printed or logged.
func TestAPIKeyRedacts(test *testing.T) {
	test.Parallel()

	key := APIKey("secret-key")

	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("test", "key", key)

	for _, output := range []string{key.String(), fmt.Sprintf("%v %s", key, key), logs.String()} {
		if strings.Contains(output, "secret-key") || !strings.Contains(output, REDACTED) {
			test.Errorf("output %q shows the key, want it redacted", output)
		}
	}
}

// TestNewAppliesOptions checks the defaults and that each option sets its value.
func TestNewAppliesOptions(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	httpClient := &http.Client{}

	defaults, err := New(Sources{}, store, httpClient)
	if nil != err {
		test.Fatalf("New() error = %v, want nil", err)
	}

	if DEFAULT_USER_AGENT != defaults.userAgent || "" != defaults.abusechAPIKey || nil == defaults.logger || nil == defaults.now {
		test.Errorf("New() defaults = %+v, want the default user agent, no key, a logger and a clock", defaults)
	}

	logger := slog.New(slog.DiscardHandler)
	configured, err := New(Sources{}, store, httpClient, WithLogger(logger), WithUserAgent("agent"), WithAbusechAPIKey("key"))
	if nil != err {
		test.Fatalf("New() with options error = %v, want nil", err)
	}

	isConfigured := logger == configured.logger && "agent" == configured.userAgent && "key" == configured.abusechAPIKey
	if !isConfigured || httpClient != configured.httpClient || store != configured.store {
		test.Errorf("New() with options = %+v, want every option applied", configured)
	}
}

// TestNewRejectsInvalidSources checks that every problem with an enabled source is reported by
// New, before any work starts, and that disabled sources aren't checked.
func TestNewRejectsInvalidSources(test *testing.T) {
	test.Parallel()

	validQuery := APIQuery{Query: "taginfo", Limit: 1}

	testCases := []struct {
		name    string
		sources Sources
		// wantErr is part of the error New must return, or "" when New must succeed.
		wantErr string
	}{
		{name: "disabled sources aren't checked", sources: Sources{JSON: []Source{{Name: "unknown"}}}},
		{name: "unknown git source", sources: Sources{Git: []Source{{Name: "unknown", Enabled: true}}}, wantErr: "no extractor"},
		{
			name:    "git url_raw not https",
			sources: Sources{Git: []Source{{Name: CRIMINALIP_SOURCE_NAME, Enabled: true, URLRaw: "http://example.com/", FileFormat: "x"}}},
			wantErr: "url_raw",
		},
		{
			name:    "git file_format missing",
			sources: Sources{Git: []Source{{Name: CRIMINALIP_SOURCE_NAME, Enabled: true, URLRaw: "https://example.com/"}}},
			wantErr: "file_format",
		},
		{name: "unknown json source", sources: Sources{JSON: []Source{{Name: "unknown", Enabled: true}}}, wantErr: "no extractor"},
		{
			name:    "csv url unparsable",
			sources: Sources{CSV: []Source{{Name: VIRIBACKTRACKER_SOURCE_NAME, Enabled: true, URL: "https://[::1"}}},
			wantErr: "parsing URL",
		},
		{name: "json url relative", sources: Sources{JSON: []Source{{Name: FEODOTRACKER_SOURCE_NAME, Enabled: true, URL: "/feed"}}}, wantErr: "url"},
		{name: "unknown api source", sources: Sources{API: []Source{{Name: "unknown", Enabled: true}}}, wantErr: "no extractor"},
		{name: "api url missing", sources: Sources{API: []Source{{Name: THREATFOX_SOURCE_NAME, Enabled: true, Query: validQuery}}}, wantErr: "url"},
		{
			name:    "api query missing",
			sources: Sources{API: []Source{{Name: THREATFOX_SOURCE_NAME, Enabled: true, URL: "https://example.com/"}}},
			wantErr: "query",
		},
		{
			name:    "threatfox without key",
			sources: Sources{API: []Source{{Name: THREATFOX_SOURCE_NAME, Enabled: true, URL: "https://example.com/", Query: validQuery}}},
			wantErr: "ABUSECH_API_KEY",
		},
		{
			name: "every problem reported",
			sources: Sources{
				Git: []Source{{Name: "first", Enabled: true}},
				API: []Source{{Name: "second", Enabled: true}},
			},
			wantErr: `source "first": no extractor for this source name` + "\n" + `source "second": no extractor for this source name`,
		},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			_, err := New(testCase.sources, newTestStore(subtest), &http.Client{})

			if "" == testCase.wantErr {
				if nil != err {
					subtest.Errorf("New() error = %v, want nil", err)
				}

				return
			}

			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("New() error = %v, want it to contain %q", err, testCase.wantErr)
			}
		})
	}
}

// TestNewRequiresDependencies checks that New refuses a missing store or HTTP client.
func TestNewRequiresDependencies(test *testing.T) {
	test.Parallel()

	if _, err := New(Sources{}, nil, &http.Client{}); nil == err {
		test.Error("New() without a store error = nil, want error")
	}

	if _, err := New(Sources{}, newTestStore(test), nil); nil == err {
		test.Error("New() without an HTTP client error = nil, want error")
	}
}

// TestAggregatorNewJobUnknownKind checks that a source whose kind isn't known is refused.
func TestAggregatorNewJobUnknownKind(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})

	if _, err := aggregator.newJob(Source{Name: CRIMINALIP_SOURCE_NAME, kind: "ftp"}); nil == err {
		test.Error(`newJob() with kind "ftp" error = nil, want error`)
	}
}

// TestAggregatorRun checks a run over one source of every kind: each is fetched the right way
// and every payload is stored.
func TestAggregatorRun(test *testing.T) {
	test.Parallel()

	gitUpstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "criminalip.csv")))
	jsonUpstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "feodotracker.json")))
	csvUpstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "viribacktracker.csv")))
	apiUpstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "threatfox_taginfo.json")))

	// Every fake upstream uses the same test certificate, so one client reaches them all.
	aggregator := newRunTestAggregator(test, apiUpstream.server.Client(), Sources{
		Git: []Source{{
			Name:       CRIMINALIP_SOURCE_NAME,
			Enabled:    true,
			URLRaw:     gitUpstream.server.URL + "/feed/",
			FileFormat: "YYYY-MM-DD.csv",
		}},
		JSON: []Source{{Name: FEODOTRACKER_SOURCE_NAME, Enabled: true, URL: jsonUpstream.server.URL}},
		CSV:  []Source{{Name: VIRIBACKTRACKER_SOURCE_NAME, Enabled: true, URL: csvUpstream.server.URL}},
		API:  []Source{{Name: THREATFOX_SOURCE_NAME, Enabled: true, URL: apiUpstream.server.URL, Query: validThreatFoxQuery}},
	})

	storedCount, err := aggregator.Run(test.Context())
	if nil != err {
		test.Fatalf("Run() error = %v, want nil", err)
	}

	// 5 Criminal IP rows, 1 Feodo Tracker entry, 5 ViriBack rows and 3 ThreatFox indicators.
	if 14 != storedCount {
		test.Errorf("Run() stored %d payloads, want 14", storedCount)
	}

	// The Git source's file is named after the fixed clock's date.
	if requests := gitUpstream.received(); 1 != len(requests) || "/feed/2026-05-09.csv" != requests[0].path {
		test.Errorf("Run() Git requests = %+v, want one for /feed/2026-05-09.csv", requests)
	}

	for _, address := range []string{"35.172.12.146", "50.16.16.211", "47.105.68.108", "94.230.141.123"} {
		readStoredPayload(test, aggregator.store, address)
	}

	// Both ThreatFox indicators for 155.94.154.152 end up in one file.
	if stored := readStoredPayload(test, aggregator.store, "155.94.154.152"); 2 != len(stored.Results) {
		test.Errorf("stored payload for 155.94.154.152 has %d results, want 2", len(stored.Results))
	}
}

// TestAggregatorRunContinuesAfterFailures checks that a failing source doesn't stop the others,
// and that every failure is returned.
func TestAggregatorRunContinuesAfterFailures(test *testing.T) {
	test.Parallel()

	failingUpstream := newFakeUpstream(test, http.StatusBadGateway, "down")
	workingUpstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "viribacktracker.csv")))

	aggregator := newRunTestAggregator(test, workingUpstream.server.Client(), Sources{
		JSON: []Source{{Name: FEODOTRACKER_SOURCE_NAME, Enabled: true, URL: failingUpstream.server.URL}},
		CSV:  []Source{{Name: VIRIBACKTRACKER_SOURCE_NAME, Enabled: true, URL: workingUpstream.server.URL}},
		API:  []Source{{Name: THREATFOX_SOURCE_NAME, Enabled: true, URL: failingUpstream.server.URL, Query: validThreatFoxQuery}},
	})

	storedCount, err := aggregator.Run(test.Context())
	if 5 != storedCount {
		test.Errorf("Run() stored %d payloads, want the 5 from the working source", storedCount)
	}

	for _, wantFailure := range []string{`processing source "feodotracker"`, `processing source "threatfox"`} {
		if nil == err || !strings.Contains(err.Error(), wantFailure) {
			test.Errorf("Run() error = %v, want it to contain %q", err, wantFailure)
		}
	}
}

// TestAggregatorRunStopsWhenCancelled checks that a cancelled run doesn't start another source.
func TestAggregatorRunStopsWhenCancelled(test *testing.T) {
	test.Parallel()

	upstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "viribacktracker.csv")))
	aggregator := newRunTestAggregator(test, upstream.server.Client(), Sources{
		CSV: []Source{{Name: VIRIBACKTRACKER_SOURCE_NAME, Enabled: true, URL: upstream.server.URL}},
	})

	ctx, cancel := context.WithCancel(test.Context())
	cancel()

	storedCount, err := aggregator.Run(ctx)
	if 0 != storedCount || !errors.Is(err, context.Canceled) {
		test.Errorf("Run() after cancelling = (%d, %v), want (0, context.Canceled)", storedCount, err)
	}

	if requests := upstream.received(); 0 != len(requests) {
		test.Errorf("Run() after cancelling sent %d requests, want 0", len(requests))
	}
}

// TestAggregatorProcessSourceLogsCounts checks the summary logged for each source.
func TestAggregatorProcessSourceLogsCounts(test *testing.T) {
	test.Parallel()

	aggregator, logs := newTestAggregator(test, &http.Client{})
	job := sourceJob{
		source: Source{Name: "test"},
		collect: func(context.Context) ([]Payload, error) {
			return []Payload{newTestPayload("1.2.3.4", "test", fixedTime, `{}`, "a")}, nil
		},
	}

	storedCount, err := aggregator.processSource(test.Context(), job)
	if nil != err || 1 != storedCount {
		test.Errorf("processSource() = (%d, %v), want (1, nil)", storedCount, err)
	}

	wantLog := `level=INFO msg="source processed" source=test payload_count=1 stored_count=1`
	if !strings.Contains(logs.String(), wantLog) {
		test.Errorf("processSource() logs = %q, want them to contain %q", logs, wantLog)
	}
}

// TestAggregatorSaveAll checks that a payload that can't be stored doesn't stop the others, and
// that every failure is returned.
func TestAggregatorSaveAll(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})
	payloads := []Payload{
		newTestPayload("1.1.1.1", "test", fixedTime, `{}`, "a"),
		{IP: newTestPayload("2.2.2.2", "", fixedTime, "", "a").IP},
		newTestPayload("3.3.3.3", "test", fixedTime, `{}`, "a"),
	}

	storedCount, err := aggregator.saveAll(test.Context(), payloads)
	if 2 != storedCount || !errors.Is(err, errInvalidPayload) || !strings.Contains(err.Error(), `"2.2.2.2"`) {
		test.Errorf("saveAll() = (%d, %v), want (2, an invalid payload error for 2.2.2.2)", storedCount, err)
	}
}

// TestAggregatorSaveAllStopsWhenCancelled checks that nothing more is stored once the run is
// cancelled.
func TestAggregatorSaveAllStopsWhenCancelled(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})

	ctx, cancel := context.WithCancel(test.Context())
	cancel()

	storedCount, err := aggregator.saveAll(ctx, []Payload{newTestPayload("1.1.1.1", "test", fixedTime, `{}`, "a")})
	if 0 != storedCount || !errors.Is(err, context.Canceled) {
		test.Errorf("saveAll() after cancelling = (%d, %v), want (0, context.Canceled)", storedCount, err)
	}

	if _, statErr := aggregator.store.root.Stat("ipv4"); !errors.Is(statErr, os.ErrNotExist) {
		test.Errorf("saveAll() after cancelling wrote files: stat error = %v", statErr)
	}
}

// TestAggregatorCollectErrors checks that feed URLs that can't be built or requested fail the
// source.
func TestAggregatorCollectErrors(test *testing.T) {
	test.Parallel()

	aggregator, _ := newTestAggregator(test, &http.Client{})
	extract := func(context.Context, io.Reader) ([]Payload, error) { return nil, nil }

	if _, err := aggregator.collectGitFile(test.Context(), Source{URLRaw: "https://[::1", FileFormat: "x"}, extract); nil == err {
		test.Error("collectGitFile() with an unparsable url_raw error = nil, want error")
	}

	if _, err := aggregator.collectFeed(test.Context(), "https://[::1", extract); nil == err {
		test.Error("collectFeed() with an unparsable URL error = nil, want error")
	}
}

// TestValidateUpstreamURL checks that only absolute https URLs are accepted.
func TestValidateUpstreamURL(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{name: "https", rawURL: "https://threatfox-api.abuse.ch/api/v1/"},
		{name: "http", rawURL: "http://threatfox-api.abuse.ch/api/v1/", wantErr: true},
		{name: "no host", rawURL: "https:///path", wantErr: true},
		{name: "relative", rawURL: "api/v1/", wantErr: true},
		{name: "empty", rawURL: "", wantErr: true},
		{name: "unparsable", rawURL: "https://[::1", wantErr: true},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if err := validateUpstreamURL(testCase.rawURL); testCase.wantErr != (nil != err) {
				subtest.Errorf("validateUpstreamURL(%q) error = %v, want error %v", testCase.rawURL, err, testCase.wantErr)
			}
		})
	}
}

// newRunTestAggregator returns an Aggregator for sources with a fixed clock and a store in a
// new temporary directory, sending requests with httpClient.
func newRunTestAggregator(testingContext testing.TB, httpClient *http.Client, sources Sources) *Aggregator {
	testingContext.Helper()

	aggregator, err := New(sources, newTestStore(testingContext), httpClient, WithAbusechAPIKey("key"))
	if nil != err {
		testingContext.Fatalf("New() error = %v, want nil", err)
	}

	aggregator.now = func() time.Time { return fixedTime }

	return aggregator
}

// TestAggregatorRunStoresExpectedPayload checks one stored file from a run end to end.
func TestAggregatorRunStoresExpectedPayload(test *testing.T) {
	test.Parallel()

	upstream := newFakeUpstream(test, http.StatusOK, string(readTestdata(test, "feodotracker.json")))
	aggregator := newRunTestAggregator(test, upstream.server.Client(), Sources{
		JSON: []Source{{Name: FEODOTRACKER_SOURCE_NAME, Enabled: true, URL: upstream.server.URL}},
	})

	if _, err := aggregator.Run(test.Context()); nil != err {
		test.Fatalf("Run() error = %v, want nil", err)
	}

	wantMetadata := `{"country":"US","firstSeen":"2025-12-30 13:56:31","lastOnline":"2026-03-12",` +
		`"hostname":"ec2-50-16-16-211.compute-1.amazonaws.com","port":443}`
	want := newTestPayload("50.16.16.211", FEODOTRACKER_SOURCE_NAME, fixedTime, wantMetadata, "qakbot")

	if diff := cmp.Diff(want, readStoredPayload(test, aggregator.store, "50.16.16.211"), payloadComparison); "" != diff {
		test.Errorf("stored payload mismatch (-want +got):\n%s", diff)
	}
}
