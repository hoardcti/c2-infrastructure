package aggregator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Output file settings. hoardCTI output is public data, so anyone may read it.
const (
	// OUTPUT_DIRECTORY_PERMISSIONS lets anyone read and list published directories.
	OUTPUT_DIRECTORY_PERMISSIONS = 0o755
	// OUTPUT_FILE_PERMISSIONS lets anyone read published files.
	OUTPUT_FILE_PERMISSIONS = 0o644
	// OUTPUT_JSON_INDENT indents published files by four spaces, as every file so far has been.
	OUTPUT_JSON_INDENT = "    "
	// RECORD_FILE_EXTENSION ends the name of every record file.
	RECORD_FILE_EXTENSION = ".json"
	// TEMPORARY_FILE_SUFFIX marks a file that is still being written. It is renamed over the
	// real file once complete, so readers never see a partial file.
	TEMPORARY_FILE_SUFFIX = ".tmp"
	// IPV6_GROUP_COUNT is the number of 16-bit groups in an IPv6 address.
	IPV6_GROUP_COUNT = 8
)

// errUnstorableAddress is returned for an address that can't name a file (see
// isStorableAddress).
var errUnstorableAddress = errors.New("address can't be stored")

// Store keeps one JSON record per IP address under an output directory. Build one with
// NewStore and call Close when done. It isn't safe for concurrent use: the aggregator updates
// records one at a time.
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

// Update reads the record for address (an empty one if there is none), lets change modify it,
// and writes it back. It reports whether the file was written: a record that change left
// exactly as it was on disk isn't rewritten, so nothing changes in Git. Every write is atomic.
//
// Files are laid out in a directory tree that mirrors the address:
//
//	ipv4/192/168/1/1.json
//	ipv6/2001/0db8/85a3/0000/0000/8a2e/0370/7334.json
//
// A version 1 file is converted to the current format as it's read (see decodeRecord).
func (store *Store) Update(address netip.Addr, change func(record *Record)) (bool, error) {
	if !isStorableAddress(address) {
		return false, fmt.Errorf("%w: %q", errUnstorableAddress, address)
	}

	name := addressFileName(address)

	record, existingContent, err := store.read(name, address)
	if nil != err {
		return false, err
	}

	change(&record)

	return store.write(name, record, existingContent)
}

// read returns the record stored under name and the file's content, or an empty record for
// address and no content if there is no file yet. It checks that the file describes address.
func (store *Store) read(name string, address netip.Addr) (Record, []byte, error) {
	content, err := store.root.ReadFile(name)

	switch {
	case errors.Is(err, fs.ErrNotExist):
		return newRecord(address), nil, nil
	case nil != err:
		return Record{}, nil, fmt.Errorf("reading %q: %w", name, err)
	}

	record, err := decodeRecord(content)
	if nil != err {
		return Record{}, nil, fmt.Errorf("decoding %q: %w", name, err)
	}

	// A file whose address doesn't match its path was edited by hand or corrupted; merging
	// into it would attribute intelligence to the wrong address.
	if address != record.IP {
		return Record{}, nil, fmt.Errorf("file %q describes %q, not %q", name, record.IP, address)
	}

	return record, content, nil
}

// write encodes record and writes it to name, unless the encoding equals existingContent. It
// reports whether the file was written.
func (store *Store) write(name string, record Record, existingContent []byte) (bool, error) {
	content, err := encodeRecord(record)
	if nil != err {
		return false, fmt.Errorf("encoding %q: %w", name, err)
	}

	if bytes.Equal(existingContent, content) {
		return false, nil
	}

	if err := store.root.MkdirAll(filepath.Dir(name), OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
		return false, fmt.Errorf("creating directory for %q: %w", name, err)
	}

	if err := writeFileAtomically(store.root, name, content); nil != err {
		return false, err
	}

	return true, nil
}

// encodeRecord encodes record as indented JSON ending with a newline. Map keys are sorted, so
// the same record always gives the same bytes. Invalid UTF-8 in upstream text, such as a key
// from a CSV feed, is replaced rather than failing the write. Data that isn't valid JSON fails.
func encodeRecord(record Record) ([]byte, error) {
	content, err := json.Marshal(
		record,
		json.Deterministic(true),
		jsontext.AllowInvalidUTF8(true),
		jsontext.WithIndent(OUTPUT_JSON_INDENT),
	)
	if nil != err {
		return nil, fmt.Errorf("encoding record: %w", err)
	}

	return append(content, '\n'), nil
}

// indexEntry is what the scheduler needs to know about one stored record.
type indexEntry struct {
	// address is the record's IP address.
	address netip.Addr
	// firstSeen is the record's first_seen; zero if no source has flagged it.
	firstSeen time.Time
	// lastAttempts maps each source name to when it last tried to look the address up.
	lastAttempts map[string]time.Time
}

// index reads every stored record and returns an entry for each, in path order, with the last
// attempts of each source in sourceNames. Only the ipv4 and ipv6 trees are read, so anything
// else in the output directory, such as a Git checkout's .git directory, is left alone.
//
// Version 1 files are rewritten in the current format as they're read, so the whole dataset
// moves to the new format in one run. A file that can't be read, decoded or upgraded doesn't
// stop the others: every failure is returned, joined together, along with the entries that
// were read. It stops early, with ctx's error, if ctx is cancelled.
func (store *Store) index(ctx context.Context, sourceNames []string) ([]indexEntry, error) {
	var (
		entries  []indexEntry
		failures []error
	)

	// visit is called by WalkDir for every file and directory under a tree, in lexical order.
	// Returning an error from it stops the walk. The function literal is a closure: it appends
	// to entries and failures from index.
	visit := func(name string, entry fs.DirEntry, err error) error {
		switch {
		case errors.Is(err, fs.ErrNotExist) && !strings.Contains(name, "/"):
			// The tree itself doesn't exist yet, such as ipv6 before the first IPv6 record.
			return nil
		case nil != err:
			failures = append(failures, fmt.Errorf("listing %q: %w", name, err))

			return nil
		case entry.IsDir() || !strings.HasSuffix(name, RECORD_FILE_EXTENSION):
			return nil
		case nil != ctx.Err():
			return fmt.Errorf("indexing records: %w", ctx.Err())
		}

		indexed, err := store.indexFile(name, sourceNames)
		if nil != err {
			failures = append(failures, err)

			return nil
		}

		entries = append(entries, indexed)

		return nil
	}

	for _, tree := range []string{"ipv4", "ipv6"} {
		if err := fs.WalkDir(store.root.FS(), tree, visit); nil != err {
			return entries, errors.Join(append(failures, err)...)
		}
	}

	return entries, errors.Join(failures...)
}

// indexFile reads one record file for index, upgrading it if it's in an older format.
func (store *Store) indexFile(name string, sourceNames []string) (indexEntry, error) {
	address, err := addressFromFileName(name)
	if nil != err {
		return indexEntry{}, err
	}

	record, content, err := store.read(name, address)
	if nil != err {
		return indexEntry{}, err
	}

	// Writing the record unchanged rewrites only files whose encoding differs, which are the
	// files in an older format.
	if _, err := store.write(name, record, content); nil != err {
		return indexEntry{}, fmt.Errorf("upgrading %q: %w", name, err)
	}

	lastAttempts := make(map[string]time.Time, len(sourceNames))
	for _, sourceName := range sourceNames {
		// The second value, ok, is false when the source never tried this address.
		if attemptedAt, ok := record.lastAttempt(sourceName); ok {
			lastAttempts[sourceName] = attemptedAt
		}
	}

	return indexEntry{address: address, firstSeen: record.FirstSeen, lastAttempts: lastAttempts}, nil
}

// addressFileName returns the path of address's file relative to the output directory.
func addressFileName(address netip.Addr) string {
	// Each IPv4 octet becomes a directory level, and the last one names the file.
	if address.Is4() {
		octets := strings.Split(address.String(), ".")

		return filepath.Join(append([]string{"ipv4"}, octets...)...) + RECORD_FILE_EXTENSION
	}

	// IPv6 addresses use their fully expanded form so every group is present.
	return filepath.Join(append([]string{"ipv6"}, expandIPv6(address)...)...) + RECORD_FILE_EXTENSION
}

// addressFromFileName is the inverse of addressFileName: it returns the address a record
// file's path names, or an error for a path that addressFileName can't have produced.
func addressFromFileName(name string) (netip.Addr, error) {
	// fs.WalkDir always uses forward slashes, whatever the operating system. The blank
	// identifier _ discards Cut's "found" result: a name without a slash fails below anyway.
	family, rest, _ := strings.Cut(strings.TrimSuffix(name, RECORD_FILE_EXTENSION), "/")
	separator := map[string]string{"ipv4": ".", "ipv6": ":"}[family]

	address, err := netip.ParseAddr(strings.ReplaceAll(rest, "/", separator))
	if nil != err || "" == separator || name != addressFileName(address) {
		return netip.Addr{}, fmt.Errorf("file %q isn't named after an address", name)
	}

	return address, nil
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

// isStorableAddress reports whether address can name a file. The zero netip.Addr isn't an
// address at all, and an IPv6 zone (the "eth0" in fe80::1%eth0) is free text chosen by
// whoever wrote the feed, so it can't safely become part of a file path. IPv4-mapped IPv6
// addresses are refused too: they would be stored under ipv6/ although they describe an IPv4
// address, splitting its history across two files.
func isStorableAddress(address netip.Addr) bool {
	return address.IsValid() && "" == address.Zone() && !address.Is4In6()
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
