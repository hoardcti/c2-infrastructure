package aggregator

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestNewStoreCreatesDirectory checks that NewStore creates a missing output directory.
func TestNewStoreCreatesDirectory(test *testing.T) {
	test.Parallel()

	outputDirectory := filepath.Join(test.TempDir(), "new", "out")

	store, err := NewStore(outputDirectory)
	if nil != err {
		test.Fatalf("NewStore(%q) error = %v, want nil", outputDirectory, err)
	}

	if err := store.Close(); nil != err {
		test.Errorf("Close() error = %v, want nil", err)
	}

	if info, err := os.Stat(outputDirectory); nil != err || !info.IsDir() {
		test.Errorf("NewStore(%q) didn't create the directory: %v", outputDirectory, err)
	}
}

// TestNewStoreErrors checks that an output directory that can't be created or opened fails.
func TestNewStoreErrors(test *testing.T) {
	test.Parallel()

	test.Run("path is a file", func(subtest *testing.T) {
		subtest.Parallel()

		filePath := filepath.Join(subtest.TempDir(), "file")
		if err := os.WriteFile(filePath, nil, 0o600); nil != err {
			subtest.Fatalf("creating file: %v", err)
		}

		if _, err := NewStore(filePath); nil == err {
			subtest.Errorf("NewStore(%q) error = nil, want error", filePath)
		}
	})

	test.Run("directory can't be opened", func(subtest *testing.T) {
		subtest.Parallel()

		if 0 == os.Geteuid() {
			subtest.Skip("root can open any directory")
		}

		lockedDirectory := filepath.Join(subtest.TempDir(), "locked")
		if err := os.Mkdir(lockedDirectory, 0o000); nil != err {
			subtest.Fatalf("creating locked directory: %v", err)
		}

		if _, err := NewStore(lockedDirectory); nil == err {
			subtest.Errorf("NewStore(%q) error = nil, want error", lockedDirectory)
		}
	})
}

// TestStoreUpdateKeepsCompleteHistory checks that updates are persisted, merged into the one
// file for the address, and never overwrite what's already stored.
func TestStoreUpdateKeepsCompleteHistory(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	address := netip.MustParseAddr("192.0.2.1")
	later := fixedTime.Add(time.Hour)

	updates := []struct {
		source string
		report Report
		at     time.Time
	}{
		{source: "shodan", report: newTestReport("", `{"port":443,"service":"nginx"}`), at: fixedTime},
		{source: "threatfox", report: newTestReport("1", `{"port":443}`, "sliver"), at: fixedTime},
		{source: "shodan", report: newTestReport("", `{"port":443,"service":"Apache"}`), at: later},
	}

	for _, update := range updates {
		isWritten, err := store.Update(address, func(record *Record) {
			record.addReports(update.source, []Report{update.report}, update.at)
		})
		if nil != err || !isWritten {
			test.Fatalf("Update(%s) = (%v, %v), want the file written", update.source, isWritten, err)
		}
	}

	stored := readStoredRecord(test, store, "192.0.2.1")

	shodanHistory := stored.Sources["shodan"].Observations
	isNginxKept := 2 == len(shodanHistory) &&
		cmp.Equal(jsontext.Value(`{"port":443,"service":"nginx"}`), shodanHistory[0].Data, recordComparison)
	if !isNginxKept {
		test.Errorf("stored shodan history = %+v, want the nginx observation kept before the Apache one", shodanHistory)
	}

	if 1 != len(stored.Sources["threatfox"].Observations) || !fixedTime.Equal(stored.FirstSeen) {
		test.Errorf("stored record = %+v, want the threatfox observation and its first_seen", stored)
	}

	// Every address has exactly one file: the one under ipv4/.
	files := listStoreFiles(test, store)
	if diff := cmp.Diff([]string{filepath.Join("ipv4", "192", "0", "2", "1.json")}, files); "" != diff {
		test.Errorf("store files mismatch (-want +got):\n%s", diff)
	}
}

// TestStoreUpdateLayout checks the file each kind of address is stored in, and that the file
// ends with a newline and has the current schema version.
func TestStoreUpdateLayout(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		address  string
		wantName string
	}{
		{address: "1.15.76.39", wantName: filepath.Join("ipv4", "1", "15", "76", "39.json")},
		{address: "2001:db8::8a2e:370:7334", wantName: filepath.Join("ipv6", "2001", "0db8", "0000", "0000", "0000", "8a2e", "0370", "7334.json")},
	}

	for _, testCase := range testCases {
		test.Run(testCase.address, func(subtest *testing.T) {
			subtest.Parallel()

			store := newTestStore(subtest)
			address := netip.MustParseAddr(testCase.address)

			if _, err := store.Update(address, func(record *Record) { record.addReports("feed", nil, fixedTime) }); nil != err {
				subtest.Fatalf("Update(%s) error = %v, want nil", testCase.address, err)
			}

			content, err := store.root.ReadFile(testCase.wantName)
			if nil != err {
				subtest.Fatalf("reading %q: %v", testCase.wantName, err)
			}

			isCurrentFormat := strings.HasSuffix(string(content), "}\n") && strings.Contains(string(content), `"schema_version": 2`)
			if !isCurrentFormat {
				subtest.Errorf("stored file = %s, want version 2 ending with a newline", content)
			}
		})
	}
}

// TestStoreUpdateSkipsUnchangedRecord checks that a record left exactly as it was isn't
// rewritten, so nothing changes in Git.
func TestStoreUpdateSkipsUnchangedRecord(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	address := netip.MustParseAddr("192.0.2.1")
	addReport := func(record *Record) {
		record.addReports("feed", []Report{newTestReport("1", `{"port":443}`, "sliver")}, fixedTime)
	}

	if isWritten, err := store.Update(address, addReport); nil != err || !isWritten {
		test.Fatalf("first Update() = (%v, %v), want the file written", isWritten, err)
	}

	if isWritten, err := store.Update(address, addReport); nil != err || isWritten {
		test.Errorf("repeated Update() = (%v, %v), want no write", isWritten, err)
	}
}

// TestStoreUpdateMigratesVersion1 checks that a version 1 file keeps every result when it's
// updated in the current format.
func TestStoreUpdateMigratesVersion1(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	address := netip.MustParseAddr("155.94.154.152")
	writeStoreFile(test, store, addressFileName(address), readTestdata(test, "published_threatfox.json"))

	isWritten, err := store.Update(address, func(record *Record) {
		record.addReports("threatfox", []Report{newTestReport("1917357", `{"port":50050}`, "cobalt strike")}, fixedTime)
	})
	if nil != err || !isWritten {
		test.Fatalf("Update() = (%v, %v), want the file written", isWritten, err)
	}

	observations := readStoredRecord(test, store, "155.94.154.152").Sources["threatfox"].Observations
	if 3 != len(observations) || !strings.Contains(string(observations[0].Data), "firstSeen") {
		test.Errorf("stored observations = %+v, want both version 1 results kept and the new one added", observations)
	}
}

// TestStoreUpdateErrors checks that an unusable address or stored file fails without changing
// anything.
func TestStoreUpdateErrors(test *testing.T) {
	test.Parallel()

	validAddress := netip.MustParseAddr("192.0.2.1")
	validName := addressFileName(validAddress)

	testCases := []struct {
		name    string
		address netip.Addr
		// prepare sets up the output directory before the update.
		prepare func(testingContext testing.TB, store *Store)
		// change is the update; by default it adds an empty check.
		change func(record *Record)
		// wantErr is part of the error Update must return.
		wantErr string
	}{
		{name: "zero address", wantErr: "can't be stored"},
		{name: "zoned address", address: netip.MustParseAddr("fe80::1%eth0"), wantErr: "can't be stored"},
		{name: "IPv4-mapped address", address: netip.MustParseAddr("::ffff:192.0.2.1"), wantErr: "can't be stored"},
		{
			name:    "corrupt file",
			address: validAddress,
			prepare: func(testingContext testing.TB, store *Store) {
				testingContext.Helper()
				writeStoreFile(testingContext, store, validName, []byte("{"))
			},
			wantErr: "decoding",
		},
		{
			name:    "file describes another address",
			address: validAddress,
			prepare: func(testingContext testing.TB, store *Store) {
				testingContext.Helper()
				writeStoreFile(testingContext, store, validName, []byte(`{"schema_version": 2, "ip": "192.0.2.2"}`))
			},
			wantErr: "describes",
		},
		{
			name:    "file can't be read",
			address: validAddress,
			prepare: func(testingContext testing.TB, store *Store) {
				testingContext.Helper()
				writeStoreFile(testingContext, store, filepath.Join(validName, "child"), nil)
			},
			wantErr: "reading",
		},
		{
			name:    "record can't be encoded",
			address: validAddress,
			change: func(record *Record) {
				record.Sources["feed"] = SourceHistory{Observations: []Observation{{Data: jsontext.Value("{")}}}
			},
			wantErr: "encoding",
		},
		{
			name:    "file can't be replaced",
			address: validAddress,
			prepare: func(testingContext testing.TB, store *Store) {
				testingContext.Helper()
				// A directory where the temporary file goes can be neither written nor removed.
				writeStoreFile(testingContext, store, filepath.Join(validName+TEMPORARY_FILE_SUFFIX, "child"), nil)
			},
			wantErr: "writing",
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			store := newTestStore(subtest)
			if nil != testCase.prepare {
				testCase.prepare(subtest, store)
			}

			change := testCase.change
			if nil == change {
				change = func(record *Record) { record.addReports("feed", nil, fixedTime) }
			}

			isWritten, err := store.Update(testCase.address, change)
			if nil == err || isWritten || !strings.Contains(err.Error(), testCase.wantErr) {
				subtest.Errorf("Update() = (%v, %v), want an error containing %q and no write", isWritten, err, testCase.wantErr)
			}
		})
	}
}

// TestStoreUpdateDirectoryCantBeCreated checks that a record whose directory can't be created
// fails without a write.
func TestStoreUpdateDirectoryCantBeCreated(test *testing.T) {
	test.Parallel()

	if 0 == os.Geteuid() {
		test.Skip("root can write to any directory")
	}

	store := newTestStore(test)
	if err := store.root.Mkdir("ipv4", 0o500); nil != err {
		test.Fatalf("creating read-only ipv4: %v", err)
	}

	isWritten, err := store.Update(netip.MustParseAddr("192.0.2.1"), func(record *Record) { record.addReports("feed", nil, fixedTime) })
	if nil == err || isWritten || !strings.Contains(err.Error(), "creating directory") {
		test.Errorf("Update() = (%v, %v), want a directory error and no write", isWritten, err)
	}
}

// TestStoreIndex checks that every record in the ipv4 and ipv6 trees is listed with its
// sources' last attempts, that other files are ignored, and that version 1 files are upgraded.
func TestStoreIndex(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	checkedAt := fixedTime.Add(-time.Hour)

	for _, address := range []string{"2001:db8::1", "192.0.2.1"} {
		if _, err := store.Update(netip.MustParseAddr(address), func(record *Record) {
			record.addReports("feed", []Report{newTestReport("1", `{}`, "sliver")}, fixedTime)
			record.addReports("shodan", nil, checkedAt)
		}); nil != err {
			test.Fatalf("Update(%s) error = %v, want nil", address, err)
		}
	}

	legacyName := addressFileName(netip.MustParseAddr("155.94.154.152"))
	writeStoreFile(test, store, legacyName, readTestdata(test, "published_threatfox.json"))
	writeStoreFile(test, store, filepath.Join(".git", "config.json"), []byte("{"))
	writeStoreFile(test, store, filepath.Join("ipv4", "README.md"), []byte("not a record"))
	writeStoreFile(test, store, "stats.json", []byte("{"))

	entries, err := store.index(test.Context(), []string{"feed", "shodan", "ipinfo"})
	if nil != err {
		test.Fatalf("index() error = %v, want nil", err)
	}

	legacyCollected := time.Date(2026, 9, 14, 11, 57, 26, 200758000, time.UTC)
	want := []indexEntry{
		{
			address:      netip.MustParseAddr("155.94.154.152"),
			firstSeen:    legacyCollected,
			lastAttempts: map[string]time.Time{},
		},
		{
			address:      netip.MustParseAddr("192.0.2.1"),
			firstSeen:    fixedTime,
			lastAttempts: map[string]time.Time{"feed": fixedTime, "shodan": checkedAt},
		},
		{
			address:      netip.MustParseAddr("2001:db8::1"),
			firstSeen:    fixedTime,
			lastAttempts: map[string]time.Time{"feed": fixedTime, "shodan": checkedAt},
		},
	}
	if diff := cmp.Diff(want, entries, cmp.AllowUnexported(indexEntry{}), recordComparison); "" != diff {
		test.Errorf("index() mismatch (-want +got):\n%s", diff)
	}

	upgraded, err := store.root.ReadFile(legacyName)
	if nil != err || !strings.Contains(string(upgraded), `"schema_version": 2`) {
		test.Errorf("version 1 file after index() = (%s, %v), want it upgraded", upgraded, err)
	}
}

// TestStoreIndexWithoutRecords checks that an output directory without ipv4 or ipv6 trees has
// no entries and isn't an error.
func TestStoreIndexWithoutRecords(test *testing.T) {
	test.Parallel()

	entries, err := newTestStore(test).index(test.Context(), nil)
	if nil != err || 0 != len(entries) {
		test.Errorf("index() of an empty store = (%v, %v), want no entries and no error", entries, err)
	}
}

// TestStoreIndexReportsBadFilesAndContinues checks that a file that can't be indexed is
// reported, and the files after it are still indexed.
func TestStoreIndexReportsBadFilesAndContinues(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	writeStoreFile(test, store, filepath.Join("ipv4", "1", "1", "1", "1.json"), []byte("{"))
	writeStoreFile(test, store, filepath.Join("ipv4", "1", "1", "1", "not-an-address.json"), []byte("{}"))
	writeStoreFile(test, store, filepath.Join("ipv4", "1", "1", "1", "01.json"), []byte("{}"))
	writeStoreFile(test, store, filepath.Join("ipv6", "1.2.3.4.json"), []byte("{}"))

	// A version 1 file whose upgrade can't be written, because a directory blocks the
	// temporary file.
	legacyName := addressFileName(netip.MustParseAddr("155.94.154.152"))
	writeStoreFile(test, store, legacyName, readTestdata(test, "published_threatfox.json"))
	writeStoreFile(test, store, filepath.Join(legacyName+TEMPORARY_FILE_SUFFIX, "child"), nil)

	if _, err := store.Update(netip.MustParseAddr("9.9.9.9"), func(record *Record) { record.addReports("feed", nil, fixedTime) }); nil != err {
		test.Fatalf("Update() error = %v, want nil", err)
	}

	entries, err := store.index(test.Context(), []string{"feed"})
	if 1 != len(entries) || netip.MustParseAddr("9.9.9.9") != entries[0].address {
		test.Errorf("index() entries = %+v, want only 9.9.9.9", entries)
	}

	for _, want := range []string{"decoding", "not-an-address.json", "01.json", "1.2.3.4.json", "upgrading"} {
		if nil == err || !strings.Contains(err.Error(), want) {
			test.Errorf("index() error = %v, want it to mention %q", err, want)
		}
	}
}

// TestStoreIndexUnreadableDirectory checks that a directory that can't be listed is reported.
func TestStoreIndexUnreadableDirectory(test *testing.T) {
	test.Parallel()

	if 0 == os.Geteuid() {
		test.Skip("root can read any directory")
	}

	store := newTestStore(test)
	if err := store.root.Mkdir("ipv4", OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
		test.Fatalf("creating ipv4: %v", err)
	}

	if err := store.root.Mkdir(filepath.Join("ipv4", "locked"), 0o000); nil != err {
		test.Fatalf("creating locked directory: %v", err)
	}

	// Cleanup restores the permissions so the temporary directory can be removed.
	test.Cleanup(func() {
		if err := store.root.Chmod(filepath.Join("ipv4", "locked"), OUTPUT_DIRECTORY_PERMISSIONS); nil != err {
			test.Errorf("unlocking directory: %v", err)
		}
	})

	if _, err := store.index(test.Context(), nil); nil == err || !strings.Contains(err.Error(), "listing") {
		test.Errorf("index() error = %v, want a listing error", err)
	}
}

// TestStoreIndexCancelled checks that indexing stops when the context is cancelled.
func TestStoreIndexCancelled(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	if _, err := store.Update(netip.MustParseAddr("192.0.2.1"), func(record *Record) { record.addReports("feed", nil, fixedTime) }); nil != err {
		test.Fatalf("Update() error = %v, want nil", err)
	}

	ctx, cancel := context.WithCancel(test.Context())
	cancel()

	if _, err := store.index(ctx, nil); !errors.Is(err, context.Canceled) {
		test.Errorf("index() of a cancelled context error = %v, want %v", err, context.Canceled)
	}
}

// TestAddressFromFileName checks that only names addressFileName produces are accepted.
func TestAddressFromFileName(test *testing.T) {
	test.Parallel()

	for _, address := range []string{"1.2.3.4", "2001:db8::1", "::"} {
		parsed := netip.MustParseAddr(address)
		// fs.WalkDir paths always use forward slashes.
		name := filepath.ToSlash(addressFileName(parsed))

		if got, err := addressFromFileName(name); nil != err || parsed != got {
			test.Errorf("addressFromFileName(%q) = (%v, %v), want %v", name, got, err, parsed)
		}
	}

	for _, name := range []string{"ipv4/1/2/3.json", "ipv4/1/2/3/04.json", "ipv5/1/2/3/4.json", "1.2.3.4.json", "ipv6/1/2/3/4.json"} {
		if _, err := addressFromFileName(name); nil == err {
			test.Errorf("addressFromFileName(%q) error = nil, want error", name)
		}
	}
}

// TestWriteFileAtomically checks that a write replaces the file and leaves no temporary file.
func TestWriteFileAtomically(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)

	for _, content := range []string{"first", "second"} {
		if err := writeFileAtomically(store.root, "file.json", []byte(content)); nil != err {
			test.Fatalf("writeFileAtomically(%q) error = %v, want nil", content, err)
		}
	}

	written, err := store.root.ReadFile("file.json")
	if nil != err || "second" != string(written) {
		test.Errorf("file content = (%q, %v), want %q", written, err, "second")
	}

	if _, err := store.root.Stat("file.json" + TEMPORARY_FILE_SUFFIX); !errors.Is(err, fs.ErrNotExist) {
		test.Errorf("temporary file left behind: stat error = %v", err)
	}
}

// TestWriteFileAtomicallyErrors checks that a failed write is reported and cleans up after
// itself where it can.
func TestWriteFileAtomicallyErrors(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		name string
		// prepare sets up the output directory before the write.
		prepare func(root *os.Root) error
		// fileName is the file being written.
		fileName string
		// wantRemoveError is true when removing the temporary file must fail too.
		wantRemoveError bool
		// wantTemporaryFile is true when the temporary path must still exist afterwards.
		wantTemporaryFile bool
	}{
		// The temporary file is never created, so there is nothing to remove.
		{name: "missing directory", fileName: filepath.Join("missing", "file.json")},
		// The temporary file is written, the rename fails, and the temporary file is removed.
		{
			name:     "target is a directory",
			prepare:  func(root *os.Root) error { return root.MkdirAll(filepath.Join("file.json", "child"), 0o700) },
			fileName: "file.json",
		},
		// A non-empty directory in the temporary file's place can be neither written nor removed.
		{
			name: "temporary path is a non-empty directory",
			prepare: func(root *os.Root) error {
				return root.MkdirAll(filepath.Join("file.json"+TEMPORARY_FILE_SUFFIX, "child"), 0o700)
			},
			fileName:          "file.json",
			wantRemoveError:   true,
			wantTemporaryFile: true,
		},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			store := newTestStore(subtest)
			prepareOutputDirectory(subtest, store, testCase.prepare)

			err := writeFileAtomically(store.root, testCase.fileName, []byte("content"))
			if nil == err {
				subtest.Fatal("writeFileAtomically() error = nil, want error")
			}

			if gotRemoveError := strings.Contains(err.Error(), "removing"); testCase.wantRemoveError != gotRemoveError {
				subtest.Errorf("writeFileAtomically() error = %v, want a removal error %v", err, testCase.wantRemoveError)
			}

			_, statErr := store.root.Stat(testCase.fileName + TEMPORARY_FILE_SUFFIX)
			if gotTemporaryFile := nil == statErr; testCase.wantTemporaryFile != gotTemporaryFile {
				subtest.Errorf("temporary path exists = %v, want %v", gotTemporaryFile, testCase.wantTemporaryFile)
			}
		})
	}
}

// prepareOutputDirectory runs prepare, if set, on store's directory before a test.
func prepareOutputDirectory(testingContext testing.TB, store *Store, prepare func(root *os.Root) error) {
	testingContext.Helper()

	if nil == prepare {
		return
	}

	if err := prepare(store.root); nil != err {
		testingContext.Fatalf("preparing output directory: %v", err)
	}
}

// listStoreFiles returns the path of every file in store's directory, in lexical order.
func listStoreFiles(testingContext testing.TB, store *Store) []string {
	testingContext.Helper()

	var files []string

	err := fs.WalkDir(store.root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if nil == err && !entry.IsDir() {
			files = append(files, filepath.FromSlash(name))
		}

		return err
	})
	if nil != err {
		testingContext.Fatalf("listing store files: %v", err)
	}

	return files
}
