package extractors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// threatFoxServer serves response for every request and records the last
// request's headers and decoded body.
func threatFoxServer(t *testing.T, status int, response string) (*httptest.Server, *http.Header, *map[string]any) {
	t.Helper()

	var header http.Header
	var body map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if http.MethodPost != r.Method {
			t.Errorf("method = %s, want POST", r.Method)
		}

		header = r.Header.Clone()
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); nil != err {
			t.Errorf("request body is not JSON: %s", raw)
		}

		w.WriteHeader(status)
		io.WriteString(w, response)
	}))
	t.Cleanup(srv.Close)

	return srv, &header, &body
}

var validQuery = map[string]any{"query": "taginfo", "tag": "c2 ", "days": float64(1), "limit": float64(1000)}

func TestThreatFox(t *testing.T) {
	t.Setenv("ABUSECH_API_KEY", "secret")

	response := `{
		"query_status": "ok",
		"data": [
			{
				"id": "1234",
				"ioc": "1.2.3.4:443",
				"ioc_type": "ip:port",
				"threat_type": "botnet_cc",
				"malware_printable": "Cobalt Strike",
				"malware_malpedia": "https://malpedia.example/cs",
				"first_seen": "2026-05-19 10:11:12 UTC",
				"reference": null
			},
			{
				"id": "5678",
				"ioc": "evil.example",
				"ioc_type": "domain",
				"malware_printable": "Other",
				"first_seen": "2026-05-19 10:11:12 UTC"
			},
			{
				"ioc": "5.6.7.8:80",
				"ioc_type": "ip:port",
				"first_seen": "2026-05-19 00:00:00 UTC"
			}
		]
	}`

	srv, header, body := threatFoxServer(t, http.StatusOK, response)

	payloads, err := ThreatFox(context.Background(), srv.Client(), srv.URL, validQuery)
	if nil != err {
		t.Fatal(err)
	}

	if "secret" != header.Get("Auth-Key") {
		t.Errorf("Auth-Key = %q, want %q", header.Get("Auth-Key"), "secret")
	}
	if "application/json" != header.Get("Accept") {
		t.Errorf("Accept = %q", header.Get("Accept"))
	}
	if "taginfo" != (*body)["query"] || "c2 " != (*body)["tag"] {
		t.Errorf("request body = %v", *body)
	}

	// The domain IOC is skipped
	if 2 != len(payloads) {
		t.Fatalf("len(payloads) = %d, want 2", len(payloads))
	}

	r := assertSingleResult(t, payloads[0], "1.2.3.4", "threatfox", "cobalt strike")
	want := map[string]any{
		"firstSeen":        "2026-05-19T10:11:12",
		"port":             "443",
		"reference":        nil,
		"malware_malpedia": "https://malpedia.example/cs",
		"id":               "1234",
		"ioc":              "1.2.3.4:443",
		"threat_type":      "botnet_cc",
	}
	for key, value := range want {
		if got, ok := r.Metadata[key]; false == ok || value != got {
			t.Errorf("metadata[%q] = %v (present %v), want %v", key, got, ok, value)
		}
	}

	// Missing optional fields fall back to Python-style defaults
	r = assertSingleResult(t, payloads[1], "5.6.7.8", "threatfox", "unknown")
	if "" != r.Metadata["id"] || "" != r.Metadata["reference"] || "" != r.Metadata["threat_type"] {
		t.Errorf("defaults not applied: %v", r.Metadata)
	}
}

func TestThreatFoxInvalidQuery(t *testing.T) {
	tests := []map[string]any{
		{"query": "taginfo"},
		{"limit": float64(10)},
		{"query": "", "limit": float64(10)},
		{"query": "taginfo", "limit": float64(0)},
		{},
	}

	for _, query := range tests {
		// No server: an invalid query must not make a request
		if _, err := ThreatFox(context.Background(), http.DefaultClient, "http://127.0.0.1:0", query); nil == err {
			t.Errorf("ThreatFox(%v) error = nil, want error", query)
		}
	}
}

func TestThreatFoxNoData(t *testing.T) {
	for _, response := range []string{
		`{"query_status": "ok", "data": []}`,
		`{"query_status": "ok", "data": null}`,
		`{"query_status": "ok"}`,
	} {
		srv, _, _ := threatFoxServer(t, http.StatusOK, response)

		payloads, err := ThreatFox(context.Background(), srv.Client(), srv.URL, validQuery)
		if nil != err || 0 != len(payloads) {
			t.Errorf("response %s: got (%v, %v), want no payloads and no error", response, payloads, err)
		}
	}
}

func TestThreatFoxErrors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		response string
	}{
		{"http error", http.StatusUnauthorized, `{}`},
		{"bad json", http.StatusOK, `{`},
		{"api error", http.StatusOK, `{"query_status": "illegal_tag", "error": "bad tag"}`},
		{"api error no message", http.StatusOK, `{"query_status": "no_result"}`},
		{"data not a list", http.StatusOK, `{"query_status": "ok", "data": "Your search did not yield any results"}`},
		{"entry not an object", http.StatusOK, `{"query_status": "ok", "data": [1]}`},
		{"ipv6 ioc", http.StatusOK, `{"query_status": "ok", "data": [{"ioc": "::1:80", "ioc_type": "ip:port", "first_seen": "2026-05-19 00:00:00 UTC"}]}`},
		{"bad first_seen", http.StatusOK, `{"query_status": "ok", "data": [{"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "first_seen": "yesterday"}]}`},
		{"missing first_seen", http.StatusOK, `{"query_status": "ok", "data": [{"ioc": "1.2.3.4:80", "ioc_type": "ip:port"}]}`},
		{"null malware", http.StatusOK, `{"query_status": "ok", "data": [{"ioc": "1.2.3.4:80", "ioc_type": "ip:port", "malware_printable": null, "first_seen": "2026-05-19 00:00:00 UTC"}]}`},
		{"non-string ioc", http.StatusOK, `{"query_status": "ok", "data": [{"ioc": 1, "ioc_type": "ip:port"}]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, _, _ := threatFoxServer(t, tt.status, tt.response)

			if _, err := ThreatFox(context.Background(), srv.Client(), srv.URL, validQuery); nil == err {
				t.Error("ThreatFox() error = nil, want error")
			}
		})
	}
}

func TestThreatFoxUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	if _, err := ThreatFox(context.Background(), http.DefaultClient, url, validQuery); nil == err {
		t.Error("ThreatFox() error = nil, want error for unreachable server")
	}
}

func TestTruthy(t *testing.T) {
	tests := []struct {
		v    any
		want bool
	}{
		{nil, false},
		{false, false},
		{true, true},
		{"", false},
		{"x", true},
		{float64(0), false},
		{float64(1), true},
		{0, false},
		{5, true},
		{[]any{}, false},
		{[]any{1}, true},
		{map[string]any{}, false},
		{map[string]any{"k": 1}, true},
		{struct{}{}, true},
	}

	for _, tt := range tests {
		if got := truthy(tt.v); tt.want != got {
			t.Errorf("truthy(%#v) = %v, want %v", tt.v, got, tt.want)
		}
	}
}
