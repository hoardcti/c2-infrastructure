package aggregator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// DefaultOutputDir is where payloads are written, relative to the working directory.
const DefaultOutputDir = "out"

// Store persists payloads under Dir.
type Store struct {
	Dir string
}

// SavePayload persists a payload to disk, merging with any existing data for that IP.
//
// Payloads are stored under ipv4/ or ipv6/ in a directory tree that mirrors
// the IP address structure, e.g.:
//
//	ipv4/192/168/1/1.json
//	ipv6/2001/0db8/85a3/0000/0000/8a2e/0370/7334.json
//
// If a file for the IP already exists, flags and results are merged and
// deduplicated rather than overwritten. Files are only written if they have
// meaningful changes beyond datetime updates. Invalid payloads are silently
// ignored.
func (s *Store) SavePayload(p payload.Payload) error {
	if false == validatePayload(p) {
		return nil
	}

	filePath, err := s.ipToPath(p.IP)
	if nil != err {
		return err
	}

	// Ensure all parent directories exist before writing
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); nil != err {
		return err
	}

	data, err := os.ReadFile(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		// First time seeing this IP — write directly
		return writeJSON(filePath, p)
	}
	if nil != err {
		return err
	}

	var existing payload.Payload
	if err := json.Unmarshal(data, &existing); nil != err {
		return fmt.Errorf("decode %s: %w", filePath, err)
	}

	// Keep a copy before merging to detect meaningful changes
	before := clonePayload(existing)

	mergeInto(&existing, p)

	// Skip writing if the only change is datetime
	if onlyDatetimeChanged(before, existing) {
		return nil
	}

	return writeJSON(filePath, existing)
}

// validatePayload reports whether p has the required fields and a valid IP.
func validatePayload(p payload.Payload) bool {
	return nil != p.Results && nil != p.Flags && validIP(p.IP)
}

// ipToPath converts an IP address string to its corresponding file path.
//
// IPv4 octets and IPv6 groups each become a directory level, with the
// final segment used as the filename.
func (s *Store) ipToPath(ip string) (string, error) {
	addr, err := netip.ParseAddr(ip)
	if nil != err {
		return "", err
	}

	var version string
	var parts []string

	if addr.Is4() {
		version = "ipv4"
		parts = strings.Split(addr.String(), ".")
	} else {
		// IPv6: use the fully-expanded form so every group is present
		version = "ipv6"
		parts = explodeIPv6(addr)
	}

	last := len(parts) - 1
	elems := append([]string{s.Dir, version}, parts[:last]...)
	elems = append(elems, parts[last]+".json")

	return filepath.Join(elems...), nil
}

// explodeIPv6 returns the eight zero-padded, lowercase hex groups of addr,
// matching Python's IPv6Address.exploded.
func explodeIPv6(addr netip.Addr) []string {
	b := addr.As16()
	groups := make([]string, 8)

	for i := range groups {
		groups[i] = fmt.Sprintf("%02x%02x", b[2*i], b[2*i+1])
	}

	return groups
}

// mergeInto merges newer payload data into existing in-place.
//
// Flags are unioned and sorted. Results are deduplicated by (source, flags)
// key: a new result replaces an existing one with the same key, but keeps its
// position and original datetime.
func mergeInto(existing *payload.Payload, newer payload.Payload) {
	// Union the flag sets and re-sort for stable output
	flags := append(slices.Clone(existing.Flags), newer.Flags...)
	slices.Sort(flags)
	existing.Flags = slices.Compact(flags)

	// Track result identity in insertion order, preserving original datetime
	var order []string
	seen := map[string]payload.Result{}

	// Process existing results first to preserve their original datetime
	for _, r := range existing.Results {
		key := resultKey(r)
		if _, ok := seen[key]; false == ok {
			order = append(order, key)
		}
		seen[key] = r
	}

	// Add new results, but if they already exist (same key), keep the old datetime
	for _, r := range newer.Results {
		key := resultKey(r)

		old, ok := seen[key]
		if false == ok {
			// New result - add it as-is
			order = append(order, key)
		} else if "" != old.Datetime && "" != r.Datetime {
			// Result already exists - preserve original datetime
			r.Datetime = old.Datetime
		}

		seen[key] = r
	}

	results := make([]payload.Result, 0, len(order))
	for _, key := range order {
		results = append(results, seen[key])
	}

	existing.Results = results
}

// onlyDatetimeChanged reports whether before and after differ only in
// their results' datetime fields.
func onlyDatetimeChanged(before, after payload.Payload) bool {
	// If flags changed, it's not just datetime
	if false == slices.Equal(before.Flags, after.Flags) {
		return false
	}

	// If result count changed, it's not just datetime
	if len(before.Results) != len(after.Results) {
		return false
	}

	// Compare each result, ignoring datetime fields
	for i := range before.Results {
		if false == equalIgnoringDatetime(before.Results[i], after.Results[i]) {
			return false
		}
	}

	return true
}

// equalIgnoringDatetime compares two results on everything but Datetime.
// Metadata is compared by its JSON encoding so that values decoded from disk
// (float64) and values produced by extractors (int, string) compare equal
// whenever they would be written identically.
func equalIgnoringDatetime(a, b payload.Result) bool {
	if a.Source != b.Source || false == slices.Equal(a.Flags, b.Flags) {
		return false
	}

	am, errA := json.Marshal(a.Metadata)
	bm, errB := json.Marshal(b.Metadata)

	return nil == errA && nil == errB && bytes.Equal(am, bm)
}

// clonePayload returns a copy of p whose slices can be replaced without
// affecting the original.
func clonePayload(p payload.Payload) payload.Payload {
	return payload.Payload{
		IP:      p.IP,
		Flags:   slices.Clone(p.Flags),
		Results: slices.Clone(p.Results),
	}
}

// writeJSON writes v to path as 4-space indented JSON.
func writeJSON(path string, v any) error {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")

	if err := enc.Encode(v); nil != err {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}
