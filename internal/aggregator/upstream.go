package aggregator

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// MAX_ERROR_SNIPPET_BYTES bounds how much of an error response is quoted in the error.
const MAX_ERROR_SNIPPET_BYTES = 512

// send sends request with the shared HTTP client and returns the response body, which must be
// at most maxBodyBytes long. It returns an error for any status other than 200 OK, quoting the
// start of the body, because upstreams such as abuse.ch explain failures there. Cancelling
// the request's context stops the request.
func (aggregator *Aggregator) send(request *http.Request, maxBodyBytes int64) ([]byte, error) {
	// Naming the program lets upstream operators contact us instead of blocking us, and some
	// CDNs block Go's default user agent.
	request.Header.Set("User-Agent", aggregator.userAgent)

	response, err := aggregator.httpClient.Do(request)
	if nil != err {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	// defer runs Close when send returns, on every return path, so the connection is always
	// released. Nothing is written to the body, so its Close error doesn't matter.
	defer response.Body.Close()

	if http.StatusOK != response.StatusCode {
		// The snippet only makes the error easier to understand, so a failure to read it is
		// ignored on purpose: _ discards the error.
		snippet, _ := io.ReadAll(io.LimitReader(response.Body, MAX_ERROR_SNIPPET_BYTES))
		// Collapse the snippet's whitespace so a pretty-printed body fits on one line.
		oneLineSnippet := strings.Join(strings.Fields(string(snippet)), " ")

		return nil, fmt.Errorf("unexpected HTTP status %d: %q", response.StatusCode, oneLineSnippet)
	}

	// Read one byte more than the limit, so an oversized body is reported rather than silently
	// cut short.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if nil != err {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if int64(len(body)) > maxBodyBytes {
		return nil, fmt.Errorf("response body is larger than %d bytes", maxBodyBytes)
	}

	return body, nil
}
