package aggregator

import (
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Output file settings. hoardCTI output is public data, so anyone may read it.
const (
	// OUTPUT_DIRECTORY_PERMISSIONS lets anyone read and list published directories.
	OUTPUT_DIRECTORY_PERMISSIONS = 0o755
	// OUTPUT_FILE_PERMISSIONS lets anyone read published files.
	OUTPUT_FILE_PERMISSIONS = 0o644
	// OUTPUT_JSON_INDENT indents published files by four spaces, as every file so far has been.
	OUTPUT_JSON_INDENT = "    "
	// TEMPORARY_FILE_SUFFIX marks a file that is still being written. It is renamed over the
	// real file once complete, so readers never see a partial file.
	TEMPORARY_FILE_SUFFIX = ".tmp"
	// IPV6_GROUP_COUNT is the number of 16-bit groups in an IPv6 address.
	IPV6_GROUP_COUNT = 8
)

// errInvalidPayload is returned by SavePayload for a payload that can't be stored.
var errInvalidPayload = errors.New("invalid payload")

// Store writes payloads under an output directory, one JSON file per IP address. Build one
// with NewStore and call Close when done.
type Store struct {
	// root is the output directory. Every file operation goes through it, and it refuses any
	// path that would leave the directory, so a crafted address can never write elsewhere.
	root *os.Root
}

// NewStore creates outputDirectory if it doesn't exist and opens it. The caller must call
// Close when done.
func NewStore(outputDirectory string) (*Store, error) {
	if err := os.MkdirAll(outputDirectory, OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
		return nil, fmt.Errorf("creating output directory: %w", err)
	}

	root, err := os.OpenRoot(outputDirectory)
	if nil != err {
		return nil, fmt.Errorf("opening output directory: %w", err)
	}

	return &Store{root: root}, nil
}

// Close releases the output directory.
func (store *Store) Close() error {
	if err := store.root.Close(); nil != err { // coverage-ignore -- this never fails on Linux.
		return fmt.Errorf("closing output directory: %w", err)
	}

	return nil
}

// SavePayload writes payload to its IP address's file, merging it with anything already
// stored there.
//
// Files are laid out in a directory tree that mirrors the address:
//
//	ipv4/192/168/1/1.json
//	ipv6/2001/0db8/85a3/0000/0000/8a2e/0370/7334.json
//
// Flags and results already in the file are merged and deduplicated rather than overwritten
// (see mergeInto). The file is only rewritten when something other than a result's datetime
// changes, so a repeated sighting doesn't create a Git diff. Every write is atomic. It returns
// an error wrapping errInvalidPayload for a payload with an unusable address or no results.
func (store *Store) SavePayload(payload Payload) error {
	// Refuse anything that can't be stored before touching the disk.
	if !isStorableAddress(payload.IP) || 0 == len(payload.Results) {
		return fmt.Errorf("%w for address %q", errInvalidPayload, payload.IP)
	}

	name := addressFileName(payload.IP)
	if err := store.root.MkdirAll(filepath.Dir(name), OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
		return fmt.Errorf("creating directory for %q: %w", name, err)
	}

	// A missing file means this is the first sighting of the address, so it's written as is.
	existingContent, err := store.root.ReadFile(name)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return writePayload(store.root, name, payload)
	case nil != err:
		return fmt.Errorf("reading %q: %w", name, err)
	}

	var existing Payload
	if err := json.Unmarshal(existingContent, &existing); nil != err {
		return fmt.Errorf("decoding %q: %w", name, err)
	}

	// Merge into a copy so the result can be compared with what is already on disk.
	merged := clonePayload(existing)
	mergeInto(&merged, payload)

	if onlyDatetimeChanged(existing, merged) {
		return nil
	}

	return writePayload(store.root, name, merged)
}

// addressFileName returns the path of address's file relative to the output directory.
func addressFileName(address netip.Addr) string {
	// Each IPv4 octet becomes a directory level, and the last one names the file.
	if address.Is4() {
		octets := strings.Split(address.String(), ".")

		return filepath.Join(append([]string{"ipv4"}, octets...)...) + ".json"
	}

	// IPv6 addresses use their fully expanded form so every group is present.
	return filepath.Join(append([]string{"ipv6"}, expandIPv6(address)...)...) + ".json"
}

// expandIPv6 returns the eight zero-padded, lower-case hexadecimal groups of address, as in
// Python's IPv6Address.exploded.
func expandIPv6(address netip.Addr) []string {
	addressBytes := address.As16()
	groups := make([]string, 0, IPV6_GROUP_COUNT)

	for i := range IPV6_GROUP_COUNT {
		groups = append(groups, hex.EncodeToString(addressBytes[2*i:2*i+2]))
	}

	return groups
}

// clonePayload returns a copy of payload whose slices can be changed without affecting the
// original.
func clonePayload(payload Payload) Payload {
	// A slice is a view onto an underlying array: assigning it doesn't copy the elements, so
	// slices.Clone is needed for the copy to be independent.
	return Payload{
		IP:      payload.IP,
		Flags:   slices.Clone(payload.Flags),
		Results: slices.Clone(payload.Results),
	}
}

// mergeInto merges newer into existing, changing existing in place.
//
// Flags are combined, sorted and deduplicated. Results are deduplicated by source and flags
// (see resultKey): a newer result replaces an existing one with the same key, but keeps its
// position and the datetime it was first collected.
func mergeInto(existing *Payload, newer Payload) {
	// Combine the flag sets, sorted so the output is stable. The existing flags are cloned
	// first because append could otherwise write into the array existing.Flags shares.
	flags := append(slices.Clone(existing.Flags), newer.Flags...)
	slices.Sort(flags)
	existing.Flags = slices.Compact(flags)

	// Maps must be created with make (or a literal) before they're written to. Go's map order
	// is random, so order records the keys in the order they were first seen.
	var order []string
	resultsByKey := make(map[string]Result, len(existing.Results)+len(newer.Results))

	// Existing results go first so they keep their position. If the file somehow holds two
	// results with the same key, the later one wins.
	for _, result := range existing.Results {
		key := resultKey(result)
		// The second value, isKnown, is false when the key isn't in the map yet.
		if _, isKnown := resultsByKey[key]; !isKnown {
			order = append(order, key)
		}

		resultsByKey[key] = result
	}

	// A newer result with a known key keeps the datetime the sighting was first collected.
	for _, result := range newer.Results {
		key := resultKey(result)
		previous, isKnown := resultsByKey[key]

		switch {
		case !isKnown:
			order = append(order, key)
		case !previous.Datetime.IsZero() && !result.Datetime.IsZero():
			result.Datetime = previous.Datetime
		}

		resultsByKey[key] = result
	}

	results := make([]Result, 0, len(order))
	for _, key := range order {
		results = append(results, resultsByKey[key])
	}

	existing.Results = results
}

// resultKey returns the key used to deduplicate results. Two results are duplicates when they
// have the same source and the same set of flags, in any order and with any repetition.
func resultKey(result Result) string {
	flags := slices.Clone(result.Flags)
	slices.Sort(flags)
	flags = slices.Compact(flags)

	// NUL can't appear in a source name or a flag, so it's a safe separator.
	return result.Source + "\x00" + strings.Join(flags, "\x00")
}

// onlyDatetimeChanged reports whether before and after differ at most in their results'
// datetimes.
func onlyDatetimeChanged(before, after Payload) bool {
	if !slices.Equal(before.Flags, after.Flags) || len(before.Results) != len(after.Results) {
		return false
	}

	for i := range before.Results {
		if !equalIgnoringDatetime(before.Results[i], after.Results[i]) {
			return false
		}
	}

	return true
}

// equalIgnoringDatetime reports whether two results are equal apart from their datetimes.
// Metadata is compared by meaning rather than by bytes, so a file whose metadata keys were
// written in a different order still counts as unchanged.
func equalIgnoringDatetime(first, second Result) bool {
	if first.Source != second.Source || !slices.Equal(first.Flags, second.Flags) {
		return false
	}

	// Canonicalize rewrites a value in place into RFC 8785 form (sorted keys, normalised
	// numbers), so it runs on copies. Invalid metadata never counts as unchanged.
	firstMetadata := first.Metadata.Clone()
	secondMetadata := second.Metadata.Clone()
	canonicalizeErr := errors.Join(firstMetadata.Canonicalize(), secondMetadata.Canonicalize())

	return nil == canonicalizeErr && bytes.Equal(firstMetadata, secondMetadata)
}

// writePayload writes payload to name inside root as indented JSON.
func writePayload(root *os.Root, name string, payload Payload) error {
	content, err := json.Marshal(
		payload,
		json.Deterministic(true),
		jsontext.WithIndent(OUTPUT_JSON_INDENT),
	)
	if nil != err {
		return fmt.Errorf("encoding %q: %w", name, err)
	}

	// Every published file ends with a newline.
	return writeFileAtomically(root, name, append(content, '\n'))
}

// writeFileAtomically writes content to name inside root so that readers never see a partial
// file: it writes a temporary file next to name, then renames it over name. If anything
// fails, the temporary file is removed.
func writeFileAtomically(root *os.Root, name string, content []byte) error {
	temporaryName := name + TEMPORARY_FILE_SUFFIX

	// WriteFile also reports the error from closing the file, which is where a full disk shows up.
	if err := root.WriteFile(temporaryName, content, OUTPUT_FILE_PERMISSIONS); nil != err {
		writeErr := fmt.Errorf("writing %q: %w", temporaryName, err)

		return errors.Join(writeErr, removeTemporaryFile(root, temporaryName))
	}

	if err := root.Rename(temporaryName, name); nil != err {
		renameErr := fmt.Errorf("replacing %q: %w", name, err)

		return errors.Join(renameErr, removeTemporaryFile(root, temporaryName))
	}

	return nil
}

// removeTemporaryFile removes a temporary file left by a failed write. A file that was never
// created isn't an error.
func removeTemporaryFile(root *os.Root, temporaryName string) error {
	err := root.Remove(temporaryName)
	if nil == err || errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	return fmt.Errorf("removing %q: %w", temporaryName, err)
}
