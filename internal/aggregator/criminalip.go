package extractors

import (
	"strings"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// CriminalIP parses a CriminalIP C2 daily feed CSV and returns a list of payloads.
//
// The feed is a CSV with columns: IP, flag, port, score, country, scanTime.
// The header row is skipped.
func CriminalIP(body string) ([]payload.Payload, error) {
	rows, err := readCSVRows(body, 6)
	if nil != err {
		return nil, err
	}

	payloads := make([]payload.Payload, 0, len(rows))

	for _, row := range rows {
		ip, flag, port, score, country, scanTime := row[0], row[1], row[2], row[3], row[4], row[5]
		flag = strings.ToLower(flag)

		payloads = append(payloads, payload.Payload{
			IP:    ip,
			Flags: []string{flag},
			Results: []payload.Result{{
				Source: "criminalip",
				// Record when this aggregator ingested the entry, not the scan time
				Datetime: payload.Now(),
				Flags:    []string{flag},
				Metadata: map[string]any{
					"port":     port,
					"score":    score,
					"country":  country,
					"scanTime": scanTime, // original scan timestamp from the feed
				},
			}},
		})
	}

	return payloads, nil
}
