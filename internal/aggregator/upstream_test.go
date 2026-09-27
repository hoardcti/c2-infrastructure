package aggregator

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// TestAggregatorSend checks that a successful response body is returned and that the
// configured User-Agent is sent.
func TestAggregatorSend(test *testing.T) {
	test.Parallel()

	upstream := newFakeUpstream(test, http.StatusOK, "body")
	aggregator, _ := newTestAggregator(test, upstream.server.Client())
	aggregator.userAgent = "test-agent/1.0"

	body, err := aggregator.send(newTestRequest(test, upstream.server.URL), MAX_FEED_BYTES)
	if nil != err {
		test.Fatalf("send() error = %v, want nil", err)
	}

	if "body" != string(body) {
		test.Errorf("send() = %q, want %q", body, "body")
	}

	requests := upstream.received()
	if 1 != len(requests) || "test-agent/1.0" != requests[0].header.Get("User-Agent") {
		test.Errorf("send() requests = %+v, want one with User-Agent %q", requests, "test-agent/1.0")
	}
}

// TestAggregatorSendErrors checks that failed requests, error statuses, oversized bodies and
// truncated bodies are all reported.
func TestAggregatorSendErrors(test *testing.T) {
	test.Parallel()

	test.Run("error status quotes the body", func(subtest *testing.T) {
		subtest.Parallel()

		// abuse.ch explains a rejected key in the body, spread over several lines.
		upstream := newFakeUpstream(subtest, http.StatusForbidden, "{\n    \"query_status\": \"unknown_auth_key\"\n}")
		aggregator, _ := newTestAggregator(subtest, upstream.server.Client())

		_, err := aggregator.send(newTestRequest(subtest, upstream.server.URL), MAX_FEED_BYTES)

		want := `unexpected HTTP status 403: "{ \"query_status\": \"unknown_auth_key\" }"`
		if nil == err || want != err.Error() {
			subtest.Errorf("send() error = %v, want %s", err, want)
		}
	})

	test.Run("body over the limit", func(subtest *testing.T) {
		subtest.Parallel()

		upstream := newFakeUpstream(subtest, http.StatusOK, "12345")
		aggregator, _ := newTestAggregator(subtest, upstream.server.Client())

		if _, err := aggregator.send(newTestRequest(subtest, upstream.server.URL), 4); nil == err {
			subtest.Error("send() of a 5-byte body with a 4-byte limit error = nil, want error")
		}
	})

	test.Run("truncated body", func(subtest *testing.T) {
		subtest.Parallel()

		// The server promises more bytes than it sends, so reading the body fails.
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(100))
			if _, err := io.WriteString(w, "short"); nil != err {
				subtest.Errorf("fake upstream: writing response: %v", err)
			}
		}))
		subtest.Cleanup(server.Close)
		aggregator, _ := newTestAggregator(subtest, server.Client())

		if _, err := aggregator.send(newTestRequest(subtest, server.URL), MAX_FEED_BYTES); nil == err {
			subtest.Error("send() of a truncated body error = nil, want error")
		}
	})

	test.Run("server unreachable", func(subtest *testing.T) {
		subtest.Parallel()

		server := httptest.NewTLSServer(http.NotFoundHandler())
		client := server.Client()
		server.Close()
		aggregator, _ := newTestAggregator(subtest, client)

		_, err := aggregator.send(newTestRequest(subtest, server.URL), MAX_FEED_BYTES)
		if nil == err || !strings.Contains(err.Error(), "sending request") {
			subtest.Errorf("send() to a closed server error = %v, want a sending error", err)
		}
	})
}

// newTestRequest returns a GET request for requestURL that is cancelled when the test ends.
func newTestRequest(testingContext testing.TB, requestURL string) *http.Request {
	testingContext.Helper()

	request, err := http.NewRequestWithContext(testingContext.Context(), http.MethodGet, requestURL, http.NoBody)
	if nil != err {
		testingContext.Fatalf("building request for %q: %v", requestURL, err)
	}

	return request
}
