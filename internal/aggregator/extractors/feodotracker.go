package extractors

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// FeodoTracker parses the Feodo Tracker JSON IP blocklist and returns a list
// of payloads.
func FeodoTracker(body string) ([]payload.Payload, error) {
	var entries []map[string]any
	if err := json.Unmarshal([]byte(body), &entries); nil != err {
		return nil, fmt.Errorf("decode feodotracker: %w", err)
	}

	payloads := make([]payload.Payload, 0, len(entries))

	for i, entry := range entries {
		if err := requireKeys(entry, "ip_address", "malware", "country", "first_seen", "last_online", "hostname", "port"); nil != err {
			return nil, fmt.Errorf("feodotracker entry %d: %w", i, err)
		}

		ip, err := stringField(entry, "ip_address")
		if nil != err {
			return nil, fmt.Errorf("feodotracker entry %d: %w", i, err)
		}

		malware, err := stringField(entry, "malware")
		if nil != err {
			return nil, fmt.Errorf("feodotracker entry %d: %w", i, err)
		}
		flag := strings.ToLower(malware)

		payloads = append(payloads, payload.Payload{
			IP:    ip,
			Flags: []string{flag},
			Results: []payload.Result{{
				Source: "feodotracker",
				// Record when this aggregator ingested the entry, not the scan time
				Datetime: payload.Now(),
				Flags:    []string{flag},
				Metadata: map[string]any{
					"country":    entry["country"],
					"firstSeen":  entry["first_seen"],
					"lastOnline": entry["last_online"],
					"hostname":   entry["hostname"],
					"port":       entry["port"],
				},
			}},
		})
	}

	return payloads, nil
}
