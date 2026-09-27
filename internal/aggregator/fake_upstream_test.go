package aggregator

import (
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
)

// fakeUpstream is a TLS test server that answers every request with a fixed status and body,
// and records each request it receives.
type fakeUpstream struct {
	// server is the running test server. Its Client trusts the server's certificate.
	server *httptest.Server
	// mutex allows one goroutine at a time to use requests: the server records requests on
	// its own goroutines while the test reads them.
	mutex sync.Mutex
	// requests holds every request received, in order.
	requests []recordedRequest
}

// recordedRequest is what a fakeUpstream saw of one request.
type recordedRequest struct {
	// method is the HTTP method, such as "GET".
	method string
	// path is the request's URL path.
	path string
	// header holds the request headers.
	header http.Header
	// body is the request body.
	body []byte
}

// newFakeUpstream starts a fakeUpstream that answers every request with status and body, and
// stops it when the test ends.
func newFakeUpstream(testingContext testing.TB, status int, body string) *fakeUpstream {
	testingContext.Helper()

	upstream := &fakeUpstream{}
	upstream.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This handler runs on the server's goroutines, so it reports problems with Errorf:
		// Fatalf would only stop this goroutine, not the test.
		requestBody, err := io.ReadAll(r.Body)
		if nil != err {
			testingContext.Errorf("fake upstream: reading request body: %v", err)
		}

		upstream.mutex.Lock()
		upstream.requests = append(upstream.requests, recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			header: r.Header.Clone(),
			body:   requestBody,
		})
		upstream.mutex.Unlock()

		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); nil != err {
			testingContext.Errorf("fake upstream: writing response: %v", err)
		}
	}))
	testingContext.Cleanup(upstream.server.Close)

	return upstream
}

// received returns a copy of every request the upstream has received so far.
func (upstream *fakeUpstream) received() []recordedRequest {
	upstream.mutex.Lock()
	// defer runs Unlock when received returns.
	defer upstream.mutex.Unlock()

	return slices.Clone(upstream.requests)
}
