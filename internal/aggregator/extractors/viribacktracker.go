package extractors

import (
	"fmt"
	"strings"
	"time"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// ViriBackTracker parses the ViriBack C2 tracker CSV and returns a list of payloads.
//
// The feed is a CSV with columns: family, login URL, IP, first seen (DD-MM-YYYY).
// The header row is skipped.
func ViriBackTracker(body string) ([]payload.Payload, error) {
	rows, err := readCSVRows(body, 4)
	if nil != err {
		return nil, err
	}

	payloads := make([]payload.Payload, 0, len(rows))

	for _, row := range rows {
		flag, login, ip, firstSeenStr := row[0], row[1], row[2], row[3]
		flag = strings.ToLower(flag)

		// Equivalent to strptime "%d-%m-%Y", which accepts unpadded days and months
		firstSeen, err := time.Parse("2-1-2006", firstSeenStr)
		if nil != err {
			return nil, fmt.Errorf("viribacktracker first seen %q: %w", firstSeenStr, err)
		}

		payloads = append(payloads, payload.Payload{
			IP:    ip,
			Flags: []string{flag},
			Results: []payload.Result{{
				Source: "viribacktracker",
				// Record when this aggregator ingested the entry, not the scan time
				Datetime: payload.Now(),
				Flags:    []string{flag},
				Metadata: map[string]any{
					"firstSeen": payload.ISOFormat(firstSeen),
					"login":     login,
				},
			}},
		})
	}

	return payloads, nil
}
