package aggregator

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Upstream request settings.
const (
	// DEFAULT_MAX_RETRIES is how many times a request is retried after a transient failure.
	DEFAULT_MAX_RETRIES = 3
	// DEFAULT_INITIAL_BACKOFF is the wait before the first retry. It doubles for each retry.
	DEFAULT_INITIAL_BACKOFF = 2 * time.Second
	// MAX_BACKOFF caps the wait between retries.
	MAX_BACKOFF = 1 * time.Minute
	// MAX_RETRY_AFTER is the longest Retry-After an upstream may ask for and still be waited
	// for. A longer one means a quota is used up, such as AbuseIPDB's daily limit, so the
	// request fails instead of stalling the run.
	MAX_RETRY_AFTER = 2 * time.Minute
	// MAX_ERROR_SNIPPET_BYTES bounds how much of an error response is quoted in the error.
	MAX_ERROR_SNIPPET_BYTES = 512
	// SECONDS_PER_MINUTE converts a per-minute rate into the per-second rate the limiter uses.
	SECONDS_PER_MINUTE = 60
)

// Kinds of upstream failure. Every error from Upstream.Fetch wraps exactly one of them, so
// callers react to what a failure means rather than to a status code: errors.Is(err,
// ErrForbidden) is true for any 402 or 403, from any upstream. Sources wrap them too, for
// failures an upstream reports in a 200 response, such as abuse.ch's unknown_auth_key.
var (
	// ErrUnauthorised means the upstream rejected the credentials (401): the key is missing,
	// wrong or revoked. Every later request would fail the same way.
	ErrUnauthorised = errors.New("the upstream rejected the API key")
	// ErrForbidden means the credentials are valid but their plan doesn't allow the request
	// (402 or 403), such as a free Shodan key asking for a host. Every later request would
	// fail the same way.
	ErrForbidden = errors.New("the API key's plan doesn't allow this request")
	// ErrRateLimited means the upstream's rate limit or quota is used up (429), after any
	// retries Fetch was allowed to make.
	ErrRateLimited = errors.New("the upstream's rate limit or quota is used up")
	// ErrNotFound means the upstream knows nothing about what was asked (404). For a lookup
	// API this isn't a failure, and sources turn it into "no reports" (see IsNotFound).
	ErrNotFound = errors.New("the upstream has nothing for this request")
	// ErrRejected means the upstream refused this particular request (any other 4xx, such as
	// AbuseIPDB's 422 for an address it doesn't accept). Other requests may still succeed.
	ErrRejected = errors.New("the upstream rejected this request")
	// ErrUnavailable means the upstream couldn't answer: a 5xx status, a status outside the
	// 4xx and 5xx ranges, or a network failure such as a timeout. It may recover later.
	ErrUnavailable = errors.New("the upstream is unavailable")
)

// StatusError is returned by Upstream.Fetch for a response whose status isn't 200 OK. It wraps
// the kind of failure its status means (see ErrUnauthorised and the others), and keeps the
// details for the error message.
type StatusError struct {
	// StatusCode is the HTTP status, such as 429.
	StatusCode int
	// Snippet is the start of the response body with whitespace collapsed and secrets removed,
	// because upstreams such as Shodan and abuse.ch explain failures there.
	Snippet string
	// RetryAfter is the wait the upstream asked for in its Retry-After header, or 0.
	RetryAfter time.Duration
}

// Error describes the failure: the status, what it means, and the upstream's explanation, such
// as `HTTP 403 Forbidden: the API key's plan doesn't allow this request: "{"error": "Requires
// membership or higher to access"}"`. It has a pointer receiver, so only a *StatusError is an
// error.
func (statusError *StatusError) Error() string {
	return fmt.Sprintf(
		"HTTP %d %s: %v: %q",
		statusError.StatusCode,
		http.StatusText(statusError.StatusCode),
		statusError.Unwrap(),
		statusError.Snippet,
	)
}

// Unwrap returns the kind of failure the status means. errors.Is calls it to look inside a
// *StatusError.
func (statusError *StatusError) Unwrap() error {
	switch code := statusError.StatusCode; {
	case http.StatusUnauthorized == code:
		return ErrUnauthorised
	case http.StatusPaymentRequired == code || http.StatusForbidden == code:
		return ErrForbidden
	case http.StatusTooManyRequests == code:
		return ErrRateLimited
	case http.StatusNotFound == code:
		return ErrNotFound
	case code >= http.StatusBadRequest && code < http.StatusInternalServerError:
		return ErrRejected
	default:
		return ErrUnavailable
	}
}

// IsNotFound reports whether err means the upstream knows nothing about what was asked (see
// ErrNotFound). Lookup APIs such as InternetDB answer 404 for an address they know nothing
// about, which isn't a failure.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}

// Upstream sends a source's requests: it waits for the source's rate limit before every
// request, retries transient failures, enforces a body size limit and keeps secrets out of
// errors. Build one per source with NewUpstream; all share the run's *http.Client.
type Upstream struct {
	// httpClient sends every request. It's shared by every source in a run.
	httpClient *http.Client
	// limiter spaces this source's requests to its configured rate, retries included.
	limiter *rate.Limiter
	// userAgent is sent with every request.
	userAgent string
	// secrets are removed from every error, in case an upstream echoes a key back.
	secrets []APIKey
	// maxRetries is how many times a transient failure is retried.
	maxRetries int
	// initialBackoff is the wait before the first retry.
	initialBackoff time.Duration
}

// NewUpstream builds an Upstream that sends at most requestsPerMinute requests a minute through
// httpClient. requestsPerMinute must be at least 1.
func NewUpstream(
	httpClient *http.Client,
	requestsPerMinute int,
	options ...UpstreamOption,
) (*Upstream, error) {
	if nil == httpClient {
		return nil, errors.New("an HTTP client is required")
	}

	if requestsPerMinute < 1 {
		return nil, fmt.Errorf("requests_per_minute is %d, want at least 1", requestsPerMinute)
	}

	// A burst of one spaces requests evenly instead of letting a backlog through at once.
	perSecond := rate.Limit(float64(requestsPerMinute) / SECONDS_PER_MINUTE)
	upstream := &Upstream{
		httpClient:     httpClient,
		limiter:        rate.NewLimiter(perSecond, 1),
		userAgent:      DEFAULT_USER_AGENT,
		maxRetries:     DEFAULT_MAX_RETRIES,
		initialBackoff: DEFAULT_INITIAL_BACKOFF,
	}
	for _, option := range options {
		option(upstream)
	}

	return upstream, nil
}

// UpstreamOption configures an Upstream built by NewUpstream.
type UpstreamOption func(*Upstream)

// WithUserAgent sets the User-Agent header sent with every request.
func WithUserAgent(userAgent string) UpstreamOption {
	return func(upstream *Upstream) { upstream.userAgent = userAgent }
}

// WithRedactedSecret removes secret from every error the Upstream returns. Empty secrets are
// ignored.
func WithRedactedSecret(secret APIKey) UpstreamOption {
	return func(upstream *Upstream) {
		if "" != secret {
			upstream.secrets = append(upstream.secrets, secret)
		}
	}
}

// Request describes an upstream request. Upstream builds a new *http.Request from it for every
// attempt, because a request body can only be sent once.
type Request struct {
	// Method is the HTTP method, such as http.MethodGet.
	Method string
	// URL is the absolute URL, built with net/url. It may hold a key in its query; Upstream
	// never shows the query in errors.
	URL string
	// Header holds request headers, such as the API key. User-Agent is set by Upstream.
	Header http.Header
	// Body is the request body, or nil for none.
	Body []byte
}

// Fetch sends request and returns the body of a 200 OK response, which must be at most
// maxBodyBytes long. Any other status returns a *StatusError, and a network failure an error
// wrapping ErrUnavailable. Fetch is only for read-only requests, which are safe to repeat:
// GETs, and POSTs that upstreams document as queries.
//
// 429, 502, 503 and 504 responses are retried up to DEFAULT_MAX_RETRIES times, waiting for
// the upstream's Retry-After or for an exponential backoff with jitter. A Retry-After longer
// than MAX_RETRY_AFTER isn't waited for. Network errors aren't retried, because the request
// may already have reached the upstream. Cancelling ctx stops any wait.
func (upstream *Upstream) Fetch(ctx context.Context, request Request, maxBodyBytes int64) ([]byte, error) {
	backoff := upstream.initialBackoff

	// The loop always ends in a return: every attempt either succeeds, fails for good, or
	// waits and tries again until the retries run out.
	for attempt := 0; ; attempt++ {
		body, err := upstream.send(ctx, request, maxBodyBytes)

		statusError, isStatusError := errors.AsType[*StatusError](err)
		isRetryable := isStatusError && isRetryableStatus(statusError.StatusCode)

		if !isRetryable || upstream.maxRetries == attempt || statusError.RetryAfter > MAX_RETRY_AFTER {
			return body, err
		}

		// Wait for the upstream's requested delay, or the backoff plus up to as much again of
		// random jitter, so sources that fail together don't retry in lockstep.
		wait := statusError.RetryAfter
		if 0 == wait {
			wait = backoff + rand.N(backoff) //nolint:gosec // G404: jitter needs no cryptographic randomness.
		}

		// A Timer delivers the current time on its channel C once the wait is over. select
		// blocks until whichever of its cases is ready first.
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()

			return nil, fmt.Errorf("waiting to retry: %w", ctx.Err())
		}

		backoff = min(2*backoff, MAX_BACKOFF)
	}
}

// send makes one attempt: it waits for the rate limiter, sends the request and reads the
// response.
func (upstream *Upstream) send(ctx context.Context, request Request, maxBodyBytes int64) ([]byte, error) {
	if err := upstream.limiter.Wait(ctx); nil != err {
		return nil, fmt.Errorf("waiting for rate limiter: %w", err)
	}

	httpRequest, err := http.NewRequestWithContext(ctx, request.Method, request.URL, bytes.NewReader(request.Body))
	if nil != err {
		// The URL may hold a key, and url.Parse's errors quote it, so it isn't wrapped.
		return nil, errors.New("building request: invalid method or URL")
	}

	// Clone gives this attempt its own copy, so the caller's header is never changed. Naming
	// the program lets upstream operators contact us instead of blocking us, and some CDNs
	// block Go's default user agent.
	httpRequest.Header = request.Header.Clone()
	if nil == httpRequest.Header {
		httpRequest.Header = http.Header{}
	}

	httpRequest.Header.Set("User-Agent", upstream.userAgent)

	response, err := upstream.httpClient.Do(httpRequest)
	if nil != err {
		// Client.Do wraps its errors in a *url.Error, whose message includes the full URL. Some
		// APIs, such as Shodan's, take the key in the URL, so only the inner error is kept and
		// the URL is reported without its query.
		if urlError, isURLError := errors.AsType[*url.Error](err); isURLError {
			err = urlError.Err
		}

		// A request stopped by the caller's context says nothing about the upstream.
		if nil != ctx.Err() {
			return nil, fmt.Errorf("sending request to %q: %w", redactURL(httpRequest.URL), err)
		}

		return nil, fmt.Errorf("sending request to %q: %w: %w", redactURL(httpRequest.URL), ErrUnavailable, err)
	}
	// defer runs Close when send returns, on every return path, so the connection is always
	// released. Nothing is written to the body, so its Close error doesn't matter.
	defer response.Body.Close()

	if http.StatusOK != response.StatusCode {
		return nil, upstream.newStatusError(response)
	}

	// Read one byte more than the limit, so an oversized body is reported rather than silently
	// cut short.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if nil != err {
		// The connection broke part-way through, which is the upstream's or the network's
		// failure rather than the request's.
		return nil, fmt.Errorf("reading response body: %w: %w", ErrUnavailable, err)
	}

	if int64(len(body)) > maxBodyBytes {
		return nil, fmt.Errorf("response body is larger than %d bytes", maxBodyBytes)
	}

	return body, nil
}

// newStatusError builds the error for a response whose status isn't 200 OK.
func (upstream *Upstream) newStatusError(response *http.Response) *StatusError {
	// The snippet only makes the error easier to understand, so a failure to read it is
	// ignored on purpose: the blank identifier _ discards the error.
	snippet, _ := io.ReadAll(io.LimitReader(response.Body, MAX_ERROR_SNIPPET_BYTES))
	// Collapse the snippet's whitespace so a pretty-printed body fits on one line.
	oneLineSnippet := strings.Join(strings.Fields(string(snippet)), " ")

	for _, secret := range upstream.secrets {
		oneLineSnippet = strings.ReplaceAll(oneLineSnippet, string(secret), REDACTED)
	}

	return &StatusError{
		StatusCode: response.StatusCode,
		Snippet:    oneLineSnippet,
		RetryAfter: parseRetryAfter(response.Header.Get("Retry-After")),
	}
}

// parseRetryAfter returns the wait a Retry-After header asks for: either a number of seconds
// or an HTTP date. It returns 0 for a missing or unparsable header, or a date in the past.
func parseRetryAfter(value string) time.Duration {
	if seconds, err := strconv.Atoi(value); nil == err {
		return max(0, time.Duration(seconds)*time.Second)
	}

	if moment, err := http.ParseTime(value); nil == err {
		return max(0, time.Until(moment))
	}

	return 0
}

// isRetryableStatus reports whether an HTTP status is worth retrying: rate limiting or a
// transient gateway failure.
func isRetryableStatus(statusCode int) bool {
	switch statusCode {
	case http.StatusTooManyRequests,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// redactURL returns requestURL without its query, fragment or user information, which may
// hold credentials, so it can be shown in errors and logs.
func redactURL(requestURL *url.URL) string {
	redacted := url.URL{Scheme: requestURL.Scheme, Host: requestURL.Host, Path: requestURL.Path}

	return redacted.String()
}
