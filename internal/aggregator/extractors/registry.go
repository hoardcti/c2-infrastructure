// Package extractors turns raw feed responses into standard payloads.
package extractors

import (
	"context"
	"net/http"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// BodyExtractor parses a fetched feed body into payloads.
type BodyExtractor func(body string) ([]payload.Payload, error)

// APIExtractor queries an API endpoint itself and returns the resulting payloads.
type APIExtractor func(ctx context.Context, client *http.Client, url string, query map[string]any) ([]payload.Payload, error)

// Registry maps a source name (as defined in sources.json) to the extractor
// for its downloaded body. To add a new source: add its extract function here.
var Registry = map[string]BodyExtractor{
	"criminalip":      CriminalIP,
	"feodotracker":    FeodoTracker,
	"viribacktracker": ViriBackTracker,
}

// APIRegistry maps a source name (as defined in sources.json) to an extractor
// that performs its own API requests.
var APIRegistry = map[string]APIExtractor{
	"threatfox": ThreatFox,
}
