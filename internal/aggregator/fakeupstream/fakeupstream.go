// Package fakeupstream provides a fake upstream API for the source packages' tests: a TLS test
// server that answers with fixed responses and records every request.
//
// It's a package of its own because every source package's tests use it, and Go can't share
// _test.go files between packages.
package fakeupstream

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// TEST_REQUESTS_PER_MINUTE is fast enough that the rate limiter never slows a test down.
const TEST_REQUESTS_PER_MINUTE = 6_000_000

// Response is one answer the server gives.
type Response struct {
	// Status is the HTTP status, such as http.StatusOK.
	Status int
	// Body is the response body.
	Body string
	// Header holds extra response headers, such as Retry-After.
	Header http.Header
}

// Request is what the server saw of one request.
type Request struct {
	// Method is the HTTP method, such as "GET".
	Method string
	// Path is the request's URL path.
	Path string
	// Query is the request's raw URL query.
	Query string
	// Header holds the request headers.
	Header http.Header
	// Body is the request body.
	Body []byte
}

// Server is a running fake upstream. Build one with New.
type Server struct {
	// server is the TLS test server. Its Client trusts the server's certificate.
	server *httptest.Server
	// mutex allows one goroutine at a time to use responses and requests: the server handles
	// requests on its own goroutines while the test reads them.
	mutex sync.Mutex
	// responses are given in order; the last one is repeated once the others are used.
	responses []Response
	// requests holds every request received, in order.
	requests []Request
}

// New starts a fake upstream that answers with first, then each of more in order, repeating
// the last response once all have been given. It stops when the test ends.
func New(testingContext testing.TB, first Response, more ...Response) *Server {
	testingContext.Helper()

	fake := &Server{responses: append([]Response{first}, more...)}
	fake.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The request comes from the test's own in-process client, so reading its body can't
		// fail; the blank identifier _ discards the error.
		requestBody, _ := io.ReadAll(r.Body)

		response := fake.record(Request{
			Method: r.Method,
			Path:   r.URL.Path,
			Query:  r.URL.RawQuery,
			Header: r.Header.Clone(),
			Body:   requestBody,
		})

		maps.Copy(w.Header(), response.Header)

		w.WriteHeader(response.Status)

		// A write fails only when the client has already given up, such as a test that
		// cancels its request, so there's nothing to report.
		_, _ = io.WriteString(w, response.Body)
	}))
	testingContext.Cleanup(fake.server.Close)

	return fake
}

// record stores request and returns the response to give it.
func (fake *Server) record(request Request) Response {
	fake.mutex.Lock()
	// defer runs Unlock when record returns.
	defer fake.mutex.Unlock()

	index := min(len(fake.requests), len(fake.responses)-1)
	fake.requests = append(fake.requests, request)

	return fake.responses[index]
}

// URL returns the server's base URL, such as "https://127.0.0.1:43210".
func (fake *Server) URL() string {
	return fake.server.URL
}

// Upstream returns an aggregator.Upstream that trusts the server and never waits for its rate
// limit.
func (fake *Server) Upstream(testingContext testing.TB, options ...aggregator.UpstreamOption) *aggregator.Upstream {
	testingContext.Helper()

	upstream, err := aggregator.NewUpstream(fake.server.Client(), TEST_REQUESTS_PER_MINUTE, options...)
	if nil == err {
		return upstream
	}

	testingContext.Fatalf("NewUpstream() error = %v, want nil", err) // coverage-ignore -- the client and the rate are always valid.
	return nil
}

// Requests returns a copy of every request the server has received so far.
func (fake *Server) Requests() []Request {
	fake.mutex.Lock()
	defer fake.mutex.Unlock()

	return slices.Clone(fake.requests)
}
