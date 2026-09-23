package extractors

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// ThreatFox queries the ThreatFox API with query and returns a payload for
// every ip:port IOC in the response. The API key is read from ABUSE_CH_KEY.
func ThreatFox(ctx context.Context, client *http.Client, url string, query map[string]any) ([]payload.Payload, error) {
	if false == truthy(query["limit"]) || false == truthy(query["query"]) {
		return nil, errors.New("invalid query: missing 'limit' or 'query' fields")
	}

	body, err := json.Marshal(query)
	if nil != err {
		return nil, fmt.Errorf("encode query: %w", err)
	}

	log.Printf("Fetching from %s with query: %v", url, query)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if nil != err {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Auth-Key", os.Getenv("ABUSE_CH_KEY"))

	resp, err := client.Do(req)
	if nil != err {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if http.StatusOK != resp.StatusCode {
		return nil, fmt.Errorf("failed to fetch from %s (HTTP %d)", url, resp.StatusCode)
	}

	var jsonResponse map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); nil != err {
		return nil, fmt.Errorf("decode response from %s: %w", url, err)
	}

	if "ok" != jsonResponse["query_status"] {
		return nil, fmt.Errorf("API error from %s: %v", url, getOr(jsonResponse, "error", "Unknown error"))
	}

	if false == truthy(jsonResponse["data"]) {
		log.Printf("No more data from %s", url)
		return nil, nil
	}

	data, ok := jsonResponse["data"].([]any)
	if false == ok {
		return nil, fmt.Errorf("unexpected data type %T from %s", jsonResponse["data"], url)
	}

	var payloads []payload.Payload

	for i, item := range data {
		entry, ok := item.(map[string]any)
		if false == ok {
			return nil, fmt.Errorf("threatfox entry %d is %T, want object", i, item)
		}

		if "ip:port" != entry["ioc_type"] {
			continue
		}

		p, err := threatFoxPayload(entry)
		if nil != err {
			return nil, fmt.Errorf("threatfox entry %d: %w", i, err)
		}

		payloads = append(payloads, p)
	}

	return payloads, nil
}

// threatFoxPayload converts a single ip:port IOC entry into a payload.
func threatFoxPayload(entry map[string]any) (payload.Payload, error) {
	ioc, ok := getOr(entry, "ioc", "").(string)
	if false == ok {
		return payload.Payload{}, fmt.Errorf("ioc is %T, want string", entry["ioc"])
	}

	parts := strings.Split(ioc, ":")
	if 2 != len(parts) {
		return payload.Payload{}, fmt.Errorf("ioc %q is not ip:port", ioc)
	}
	ip, port := parts[0], parts[1]

	malware, ok := getOr(entry, "malware_printable", "unknown").(string)
	if false == ok {
		return payload.Payload{}, fmt.Errorf("malware_printable is %T, want string", entry["malware_printable"])
	}
	flag := strings.ToLower(malware)

	firstSeenStr, ok := getOr(entry, "first_seen", "").(string)
	if false == ok {
		return payload.Payload{}, fmt.Errorf("first_seen is %T, want string", entry["first_seen"])
	}

	// Equivalent to strptime "%Y-%m-%d %H:%M:%S %Z", keeping the wall clock time
	firstSeen, err := time.Parse("2006-01-02 15:04:05 MST", firstSeenStr)
	if nil != err {
		return payload.Payload{}, fmt.Errorf("first_seen %q: %w", firstSeenStr, err)
	}

	return payload.Payload{
		IP:    ip,
		Flags: []string{flag},
		Results: []payload.Result{{
			Source: "threatfox",
			// Record when this aggregator ingested the entry, not the scan time
			Datetime: payload.Now(),
			Flags:    []string{flag},
			Metadata: map[string]any{
				"firstSeen":        payload.ISOFormat(firstSeen),
				"port":             port,
				"reference":        getOr(entry, "reference", ""),
				"malware_malpedia": getOr(entry, "malware_malpedia", ""),
				"id":               getOr(entry, "id", ""),
				"ioc":              ioc,
				"threat_type":      getOr(entry, "threat_type", ""),
			},
		}},
	}, nil
}

// truthy mirrors Python truthiness for values decoded from JSON.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case string:
		return "" != v
	case float64:
		return 0 != v
	case int:
		return 0 != v
	case []any:
		return 0 != len(v)
	case map[string]any:
		return 0 != len(v)
	default:
		return true
	}
}
