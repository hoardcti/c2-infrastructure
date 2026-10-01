package aggregator

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"testing/iotest"
	"testing/synctest"
	"time"
)

// TEST_REQUESTS_PER_MINUTE is fast enough that the rate limiter never slows a test down.
const TEST_REQUESTS_PER_MINUTE = 6_000_000

// fakeTransport answers requests in-process with fixed responses, without the goroutines a
// real connection needs, so testing/synctest can control time while it's used. It records
// every request.
type fakeTransport struct {
	// mutex allows one goroutine at a time to use the fields below.
	mutex sync.Mutex
	// statuses are answered in order; the last one is repeated.
	statuses []int
	// header is sent with every response.
	header http.Header
	// body is the body of every response.
	body string
	// requests holds every request received, in order.
	requests []*http.Request
}

// RoundTrip answers request. Having this method makes fakeTransport an http.RoundTripper.
func (transport *fakeTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()

	status := transport.statuses[min(len(transport.requests), len(transport.statuses)-1)]
	transport.requests = append(transport.requests, request)

	return &http.Response{
		StatusCode: status,
		Header:     transport.header.Clone(),
		Body:       io.NopCloser(strings.NewReader(transport.body)),
		Request:    request,
	}, nil
}

// requestCount returns how many requests the transport has answered.
func (transport *fakeTransport) requestCount() int {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()

	return len(transport.requests)
}

// newTestUpstream returns an Upstream that sends requests through transport at
// requestsPerMinute.
func newTestUpstream(
	testingContext testing.TB,
	transport http.RoundTripper,
	requestsPerMinute int,
	options ...UpstreamOption,
) *Upstream {
	testingContext.Helper()

	upstream, err := NewUpstream(&http.Client{Transport: transport}, requestsPerMinute, options...)
	if nil != err {
		testingContext.Fatalf("NewUpstream() error = %v, want nil", err)
	}

	return upstream
}

// TestNewUpstreamRejectsInvalidSettings checks the settings NewUpstream refuses.
func TestNewUpstreamRejectsInvalidSettings(test *testing.T) {
	test.Parallel()

	if _, err := NewUpstream(nil, 1); nil == err {
		test.Error("NewUpstream(nil client) error = nil, want error")
	}

	if _, err := NewUpstream(&http.Client{}, 0); nil == err || !strings.Contains(err.Error(), "requests_per_minute") {
		test.Errorf("NewUpstream(0 per minute) error = %v, want a requests_per_minute error", err)
	}
}

// TestUpstreamFetch checks a successful request against a real TLS server: the method, URL,
// headers and body sent, and the body returned. The caller's header must not be changed.
func TestUpstreamFetch(test *testing.T) {
	test.Parallel()

	var received *http.Request

	var receivedBody []byte

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r
		receivedBody, _ = io.ReadAll(r.Body) // The test fails below if the body is missing.

		_, _ = io.WriteString(w, "answer") // The test fails below if the answer is missing.
	}))
	test.Cleanup(server.Close)

	upstream, err := NewUpstream(server.Client(), TEST_REQUESTS_PER_MINUTE, WithUserAgent("agent"))
	if nil != err {
		test.Fatalf("NewUpstream() error = %v, want nil", err)
	}

	header := http.Header{}
	header.Set("Auth-Key", "secret")

	body, err := upstream.Fetch(test.Context(), Request{
		Method: http.MethodPost,
		URL:    server.URL + "/path?query=1",
		Header: header,
		Body:   []byte("request"),
	}, 1024)
	if nil != err || "answer" != string(body) {
		test.Fatalf("Fetch() = (%q, %v), want %q", body, err, "answer")
	}

	isExpectedRequest := http.MethodPost == received.Method && "/path" == received.URL.Path &&
		"query=1" == received.URL.RawQuery && "request" == string(receivedBody) &&
		"secret" == received.Header.Get("Auth-Key") && "agent" == received.Header.Get("User-Agent")
	if !isExpectedRequest {
		test.Errorf("Fetch() sent %s %s with headers %v and body %q, want the request as given", received.Method, received.URL, received.Header, receivedBody)
	}

	if "" != header.Get("User-Agent") {
		test.Errorf("Fetch() changed the caller's header to %v", header)
	}
}

// TestUpstreamFetchStatusError checks that a status other than 200 returns a *StatusError
// whose snippet is on one line, bounded, and free of the registered secret.
func TestUpstreamFetchStatusError(test *testing.T) {
	test.Parallel()

	transport := &fakeTransport{
		statuses: []int{http.StatusNotFound},
		body:     "{\n  \"error\": \"no key secret-key here\"\n}" + strings.Repeat("x", MAX_ERROR_SNIPPET_BYTES),
	}
	upstream := newTestUpstream(test, transport, TEST_REQUESTS_PER_MINUTE, WithRedactedSecret("secret-key"), WithRedactedSecret(""))

	_, err := upstream.Fetch(test.Context(), Request{Method: http.MethodGet, URL: "https://example.com/"}, 1024)

	statusError, ok := errors.AsType[*StatusError](err)
	if !ok || http.StatusNotFound != statusError.StatusCode || !IsNotFound(err) {
		test.Fatalf("Fetch() error = %v, want a 404 *StatusError", err)
	}

	isRedactedSnippet := strings.HasPrefix(statusError.Snippet, `{ "error": "no key `+REDACTED) &&
		!strings.Contains(err.Error(), "secret-key") && len(statusError.Snippet) <= MAX_ERROR_SNIPPET_BYTES
	if !isRedactedSnippet {
		test.Errorf("Fetch() snippet = %q, want one bounded line with the secret redacted", statusError.Snippet)
	}

	if 1 != transport.requestCount() {
		test.Errorf("Fetch() sent %d requests for a 404, want 1", transport.requestCount())
	}

	if IsNotFound(errors.New("other")) {
		test.Error("IsNotFound(non-status error) = true, want false")
	}
}

// retryTestCase is one case of TestUpstreamFetchRetries.
type retryTestCase struct {
	name     string
	statuses []int
	// retryAfter is the Retry-After header of every response, if any.
	retryAfter string
	// wantStatus is the status of the error Fetch returns, or 0 for success.
	wantStatus   int
	wantRequests int
	// wantMinimumWait and wantMaximumWait bound the total time spent waiting.
	wantMinimumWait time.Duration
	wantMaximumWait time.Duration
}

// TestUpstreamFetchRetries checks which responses are retried, how long Fetch waits before
// each retry, and that the last response is returned once the retries run out. Time is
// controlled by testing/synctest, so the waits take no real time.
func TestUpstreamFetchRetries(test *testing.T) {
	test.Parallel()

	testCases := []retryTestCase{
		{
			name:     "transient failures then success",
			statuses: []int{http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusOK},
			// Backoff of 2s then 4s, each plus up to as much again of jitter.
			wantRequests: 3, wantMinimumWait: 6 * time.Second, wantMaximumWait: 12 * time.Second,
		},
		{
			name:         "retries run out",
			statuses:     []int{http.StatusGatewayTimeout},
			wantStatus:   http.StatusGatewayTimeout,
			wantRequests: DEFAULT_MAX_RETRIES + 1, wantMinimumWait: 14 * time.Second, wantMaximumWait: 28 * time.Second,
		},
		{
			name:         "Retry-After in seconds",
			statuses:     []int{http.StatusTooManyRequests, http.StatusOK},
			retryAfter:   "7",
			wantRequests: 2, wantMinimumWait: 7 * time.Second, wantMaximumWait: 7 * time.Second,
		},
		{
			name:       "Retry-After beyond the limit fails at once",
			statuses:   []int{http.StatusTooManyRequests, http.StatusOK},
			retryAfter: "86400",
			wantStatus: http.StatusTooManyRequests, wantRequests: 1,
		},
		{
			name:       "client errors aren't retried",
			statuses:   []int{http.StatusUnauthorized, http.StatusOK},
			wantStatus: http.StatusUnauthorized, wantRequests: 1,
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			// synctest.Test runs the function in a bubble with a fake clock, which jumps
			// forward whenever every goroutine in the bubble is waiting.
			synctest.Test(subtest, func(subtest *testing.T) { checkFetchRetries(subtest, testCase) })
		})
	}
}

// checkFetchRetries runs one retryTestCase inside a synctest bubble.
func checkFetchRetries(test *testing.T, testCase retryTestCase) {
	test.Helper()

	header := http.Header{}
	if "" != testCase.retryAfter {
		header.Set("Retry-After", testCase.retryAfter)
	}

	transport := &fakeTransport{statuses: testCase.statuses, header: header}
	upstream := newTestUpstream(test, transport, TEST_REQUESTS_PER_MINUTE)

	started := time.Now()
	_, err := upstream.Fetch(test.Context(), Request{Method: http.MethodGet, URL: "https://example.com/"}, 1024)
	waited := time.Since(started)

	gotStatus := 0
	if statusError, ok := errors.AsType[*StatusError](err); ok {
		gotStatus = statusError.StatusCode
	}

	if testCase.wantStatus != gotStatus || (0 == testCase.wantStatus) != (nil == err) {
		test.Errorf("Fetch() error = %v, want status %d", err, testCase.wantStatus)
	}

	if testCase.wantRequests != transport.requestCount() {
		test.Errorf("Fetch() sent %d requests, want %d", transport.requestCount(), testCase.wantRequests)
	}

	if waited < testCase.wantMinimumWait || waited > testCase.wantMaximumWait {
		test.Errorf("Fetch() waited %v, want %v to %v", waited, testCase.wantMinimumWait, testCase.wantMaximumWait)
	}
}

// TestUpstreamFetchCancelledWhileWaiting checks that cancelling the context stops a wait
// before a retry.
func TestUpstreamFetchCancelledWhileWaiting(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(test *testing.T) {
		transport := &fakeTransport{statuses: []int{http.StatusServiceUnavailable}}
		upstream := newTestUpstream(test, transport, TEST_REQUESTS_PER_MINUTE)

		ctx, cancel := context.WithTimeout(test.Context(), time.Second)
		defer cancel()

		_, err := upstream.Fetch(ctx, Request{Method: http.MethodGet, URL: "https://example.com/"}, 1024)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "waiting to retry") {
			test.Errorf("Fetch() error = %v, want the wait cancelled", err)
		}
	})
}

// TestUpstreamFetchRateLimit checks that requests are spaced to the configured rate, and that
// a cancelled context stops the wait for the limiter.
func TestUpstreamFetchRateLimit(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(test *testing.T) {
		transport := &fakeTransport{statuses: []int{http.StatusOK}}
		upstream := newTestUpstream(test, transport, 30)
		request := Request{Method: http.MethodGet, URL: "https://example.com/"}

		started := time.Now()

		for range 3 {
			if _, err := upstream.Fetch(test.Context(), request, 1024); nil != err {
				test.Fatalf("Fetch() error = %v, want nil", err)
			}
		}

		// 30 a minute is one every 2 seconds; the first request doesn't wait.
		if waited := time.Since(started); 4*time.Second != waited {
			test.Errorf("3 Fetch() calls at 30 a minute took %v, want 4s", waited)
		}

		ctx, cancel := context.WithCancel(test.Context())
		cancel()

		if _, err := upstream.Fetch(ctx, request, 1024); !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "rate limiter") {
			test.Errorf("Fetch() with a cancelled context error = %v, want the limiter wait cancelled", err)
		}
	})
}

// TestUpstreamFetchRetryAfterDate checks that a Retry-After given as an HTTP date is honoured.
func TestUpstreamFetchRetryAfterDate(test *testing.T) {
	test.Parallel()

	synctest.Test(test, func(test *testing.T) {
		header := http.Header{}
		header.Set("Retry-After", time.Now().Add(30*time.Second).UTC().Format(http.TimeFormat))

		transport := &fakeTransport{statuses: []int{http.StatusTooManyRequests, http.StatusOK}, header: header}
		upstream := newTestUpstream(test, transport, TEST_REQUESTS_PER_MINUTE)

		started := time.Now()
		if _, err := upstream.Fetch(test.Context(), Request{Method: http.MethodGet, URL: "https://example.com/"}, 1024); nil != err {
			test.Fatalf("Fetch() error = %v, want nil", err)
		}

		if waited := time.Since(started); 30*time.Second != waited {
			test.Errorf("Fetch() waited %v, want 30s", waited)
		}
	})
}

// TestParseRetryAfter checks the Retry-After forms that give no wait.
func TestParseRetryAfter(test *testing.T) {
	test.Parallel()

	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)

	for _, value := range []string{"", "soon", "-5", past} {
		if wait := parseRetryAfter(value); 0 != wait {
			test.Errorf("parseRetryAfter(%q) = %v, want 0", value, wait)
		}
	}
}

// TestUpstreamFetchFailures checks failures that happen before or while reading a response,
// and that a key in the URL never appears in the error.
func TestUpstreamFetchFailures(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name      string
		transport http.RoundTripper
		url       string
		// wantErr is part of the error Fetch must return.
		wantErr string
	}{
		{
			name:    "connection refused",
			url:     "https://127.0.0.1:1/host/1.2.3.4?key=secret-key",
			wantErr: `sending request to "https://127.0.0.1:1/host/1.2.3.4"`,
		},
		{name: "invalid URL", url: "https://[::1/?key=secret-key", wantErr: "building request"},
		{
			name:      "body too large",
			transport: &fakeTransport{statuses: []int{http.StatusOK}, body: "12345"},
			url:       "https://example.com/",
			wantErr:   "larger than 4 bytes",
		},
		{
			name:      "body can't be read",
			transport: failingBodyTransport{},
			url:       "https://example.com/",
			wantErr:   "reading response body",
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			transport := testCase.transport
			if nil == transport {
				transport = http.DefaultTransport
			}

			upstream := newTestUpstream(subtest, transport, TEST_REQUESTS_PER_MINUTE)

			_, err := upstream.Fetch(subtest.Context(), Request{Method: http.MethodGet, URL: testCase.url}, 4)
			if nil == err || !strings.Contains(err.Error(), testCase.wantErr) || strings.Contains(err.Error(), "secret-key") {
				subtest.Errorf("Fetch() error = %v, want one containing %q and no key", err, testCase.wantErr)
			}
		})
	}
}

// failingBodyTransport answers every request with a body that fails when read.
type failingBodyTransport struct{}

// RoundTrip answers request with a failing body.
func (transport failingBodyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(iotest.ErrReader(errors.New("connection reset"))),
		Request:    request,
	}, nil
}
