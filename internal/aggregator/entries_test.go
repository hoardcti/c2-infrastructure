package aggregator

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
)

// TestParseAddress checks which upstream addresses are accepted.
func TestParseAddress(test *testing.T) {
	test.Parallel()

	for _, rawAddress := range []string{"192.0.2.1", "2001:db8::1"} {
		if address, err := ParseAddress(rawAddress); nil != err || netip.MustParseAddr(rawAddress) != address {
			test.Errorf("ParseAddress(%q) = (%v, %v), want the address", rawAddress, address, err)
		}
	}

	for _, rawAddress := range []string{"", "not an address", "fe80::1%eth0", "::ffff:192.0.2.1", "192.0.2.1/24"} {
		if _, err := ParseAddress(rawAddress); nil == err {
			test.Errorf("ParseAddress(%q) error = nil, want error", rawAddress)
		}
	}
}

// TestConvertEntries checks that converted entries are kept in order, unsupported entries are
// skipped at debug level, and malformed ones are skipped with a warning.
func TestConvertEntries(test *testing.T) {
	test.Parallel()

	var logs bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	convert := func(entry string) (Sighting, error) {
		switch entry {
		case "domain":
			return Sighting{}, ErrUnsupportedEntry
		case "broken":
			return Sighting{}, errors.New("broken entry")
		}

		return Sighting{Address: netip.MustParseAddr(entry)}, nil
	}

	sightings := ConvertEntries(test.Context(), logger, "test", []string{"192.0.2.1", "domain", "broken", "192.0.2.2"}, convert)

	if 2 != len(sightings) || "192.0.2.2" != sightings[1].Address.String() {
		test.Errorf("ConvertEntries() = %+v, want the two addresses in order", sightings)
	}

	for _, want := range []string{
		`level=DEBUG msg="skipping unsupported entry" source=test entry_index=1`,
		`level=WARN msg="skipping malformed entry" source=test entry_index=2 error="broken entry"`,
	} {
		if !strings.Contains(logs.String(), want) {
			test.Errorf("ConvertEntries() logs = %q, want them to contain %q", logs.String(), want)
		}
	}
}
