package aggregator

import (
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// TestNewStoreCreatesDirectory checks that a missing output directory is created.
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

// TestNewStoreErrors checks that an output directory that can't be created or opened is
// reported.
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

// TestStoreSavePayloadNewFile checks that the first sighting of an address is written as is,
// at the path that mirrors the address.
func TestStoreSavePayloadNewFile(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	payload := newTestPayload("10.0.0.1", "source", fixedTime, `{"port":"443"}`, "z", "a")

	if err := store.SavePayload(payload); nil != err {
		test.Fatalf("SavePayload() error = %v, want nil", err)
	}

	// The flags aren't sorted on the first write: nothing has been merged yet.
	if diff := cmp.Diff(payload, readStoredPayload(test, store, "10.0.0.1"), payloadComparison); "" != diff {
		test.Errorf("stored payload mismatch (-want +got):\n%s", diff)
	}

	info, err := store.root.Stat(filepath.Join("ipv4", "10", "0", "0", "1.json"))
	if nil != err {
		test.Fatalf("stat of stored file: %v", err)
	}

	if OUTPUT_FILE_PERMISSIONS != info.Mode().Perm() {
		test.Errorf("stored file permissions = %v, want %v", info.Mode().Perm(), fs.FileMode(OUTPUT_FILE_PERMISSIONS))
	}
}

// TestStoreSavePayloadMerges checks that a second sighting is merged into the existing file.
func TestStoreSavePayloadMerges(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	laterTime := fixedTime.Add(time.Hour)

	for _, payload := range []Payload{
		newTestPayload("10.0.0.1", "first", fixedTime, `{}`, "a"),
		newTestPayload("10.0.0.1", "second", laterTime, `{}`, "b"),
	} {
		if err := store.SavePayload(payload); nil != err {
			test.Fatalf("SavePayload() error = %v, want nil", err)
		}
	}

	want := Payload{
		IP:    netip.MustParseAddr("10.0.0.1"),
		Flags: []string{"a", "b"},
		Results: []Result{
			{Source: "first", Datetime: isoTime(fixedTime), Flags: []string{"a"}, Metadata: []byte(`{}`)},
			{Source: "second", Datetime: isoTime(laterTime), Flags: []string{"b"}, Metadata: []byte(`{}`)},
		},
	}
	if diff := cmp.Diff(want, readStoredPayload(test, store, "10.0.0.1"), payloadComparison); "" != diff {
		test.Errorf("merged payload mismatch (-want +got):\n%s", diff)
	}
}

// TestStoreSavePayloadSkipsDatetimeOnlyChange checks that a repeated sighting doesn't rewrite
// the file, so the published data doesn't change every hour.
func TestStoreSavePayloadSkipsDatetimeOnlyChange(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	name := filepath.Join("ipv4", "10", "0", "0", "1.json")

	if err := store.SavePayload(newTestPayload("10.0.0.1", "source", fixedTime, `{"port": 443}`, "a")); nil != err {
		test.Fatalf("first SavePayload() error = %v, want nil", err)
	}

	// Backdate the file so a rewrite would show in its modification time.
	backdated := fixedTime.Add(-time.Hour)
	if err := store.root.Chtimes(name, backdated, backdated); nil != err {
		test.Fatalf("backdating stored file: %v", err)
	}

	// The same sighting an hour later, with the metadata written differently.
	repeated := newTestPayload("10.0.0.1", "source", fixedTime.Add(time.Hour), `{"port":443.0}`, "a")
	if err := store.SavePayload(repeated); nil != err {
		test.Fatalf("second SavePayload() error = %v, want nil", err)
	}

	info, err := store.root.Stat(name)
	if nil != err {
		test.Fatalf("stat of stored file: %v", err)
	}

	if !backdated.Equal(info.ModTime()) {
		test.Errorf("stored file modified at %v, want it left alone at %v", info.ModTime(), backdated)
	}
}

// TestStoreSavePayloadErrors checks that payloads that can't be stored, and files that can't
// be read or written, are reported.
func TestStoreSavePayloadErrors(test *testing.T) {
	test.Parallel()

	validPayload := newTestPayload("10.0.0.1", "source", fixedTime, `{}`, "a")

	testCases := []struct {
		name string
		// prepare sets up the output directory before the payload is saved.
		prepare func(root *os.Root) error
		payload Payload
		// wantInvalid is true when the error must wrap errInvalidPayload.
		wantInvalid bool
	}{
		{name: "zero address", payload: Payload{Results: validPayload.Results}, wantInvalid: true},
		{
			name:        "zoned address",
			payload:     Payload{IP: netip.MustParseAddr("fe80::1%eth0"), Results: validPayload.Results},
			wantInvalid: true,
		},
		{name: "no results", payload: Payload{IP: validPayload.IP}, wantInvalid: true},
		{
			name:    "directory blocked by a file",
			prepare: func(root *os.Root) error { return root.WriteFile("ipv4", nil, 0o600) },
			payload: validPayload,
		},
		{
			name: "file is a directory",
			prepare: func(root *os.Root) error {
				return root.MkdirAll(filepath.Join("ipv4", "10", "0", "0", "1.json"), 0o700)
			},
			payload: validPayload,
		},
		{
			name: "existing file isn't JSON",
			prepare: func(root *os.Root) error {
				if err := root.MkdirAll(filepath.Join("ipv4", "10", "0", "0"), 0o700); nil != err {
					return err
				}

				return root.WriteFile(filepath.Join("ipv4", "10", "0", "0", "1.json"), []byte("{not json"), 0o600)
			},
			payload: validPayload,
		},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			store := newTestStore(subtest)
			prepareOutputDirectory(subtest, store, testCase.prepare)

			err := store.SavePayload(testCase.payload)
			if nil == err {
				subtest.Fatal("SavePayload() error = nil, want error")
			}

			if testCase.wantInvalid != errors.Is(err, errInvalidPayload) {
				subtest.Errorf("SavePayload() error = %v, want errInvalidPayload %v", err, testCase.wantInvalid)
			}
		})
	}
}

// TestAddressFileName checks the file path of IPv4, IPv6 and IPv4-mapped IPv6 addresses.
func TestAddressFileName(test *testing.T) {
	test.Parallel()

	testCases := []struct {
		address string
		want    string
	}{
		{address: "192.168.1.1", want: filepath.Join("ipv4", "192", "168", "1", "1.json")},
		{
			address: "2001:db8:85a3::8a2e:370:7334",
			want:    filepath.Join("ipv6", "2001", "0db8", "85a3", "0000", "0000", "8a2e", "0370", "7334.json"),
		},
		{address: "::1", want: filepath.Join("ipv6", "0000", "0000", "0000", "0000", "0000", "0000", "0000", "0001.json")},
		{
			address: "::ffff:1.2.3.4",
			want:    filepath.Join("ipv6", "0000", "0000", "0000", "0000", "0000", "ffff", "0102", "0304.json"),
		},
		{address: "2001:DB8::ABCD", want: filepath.Join("ipv6", "2001", "0db8", "0000", "0000", "0000", "0000", "0000", "abcd.json")},
	}

	for _, testCase := range testCases {
		test.Run(testCase.address, func(subtest *testing.T) {
			subtest.Parallel()

			if got := addressFileName(netip.MustParseAddr(testCase.address)); testCase.want != got {
				subtest.Errorf("addressFileName(%s) = %q, want %q", testCase.address, got, testCase.want)
			}
		})
	}
}

// TestMergeInto checks that flags are combined and sorted, and that a repeated result keeps
// its position and first-collected datetime but takes the newer metadata.
func TestMergeInto(test *testing.T) {
	test.Parallel()

	laterTime := fixedTime.Add(time.Hour)
	existing := Payload{
		Flags: []string{"b", "a"},
		Results: []Result{
			{Source: "s1", Datetime: isoTime(fixedTime), Flags: []string{"a"}, Metadata: []byte(`{"v":"1"}`)},
			{Source: "s2", Datetime: isoTime(fixedTime), Flags: []string{"b"}},
		},
	}
	newer := Payload{
		Flags: []string{"c", "a"},
		Results: []Result{
			{Source: "s1", Datetime: isoTime(laterTime), Flags: []string{"a"}, Metadata: []byte(`{"v":"2"}`)},
			{Source: "s3", Datetime: isoTime(laterTime), Flags: []string{"c"}},
		},
	}

	mergeInto(&existing, newer)

	want := Payload{
		Flags: []string{"a", "b", "c"},
		Results: []Result{
			{Source: "s1", Datetime: isoTime(fixedTime), Flags: []string{"a"}, Metadata: []byte(`{"v":"2"}`)},
			{Source: "s2", Datetime: isoTime(fixedTime), Flags: []string{"b"}},
			{Source: "s3", Datetime: isoTime(laterTime), Flags: []string{"c"}},
		},
	}
	if diff := cmp.Diff(want, existing, payloadComparison); "" != diff {
		test.Errorf("mergeInto() mismatch (-want +got):\n%s", diff)
	}

	if !laterTime.Equal(time.Time(newer.Results[0].Datetime)) {
		test.Error("mergeInto() changed the newer payload's datetime")
	}
}

// TestMergeIntoDatetimeKeptOnlyWhenBothSet checks that a result without a datetime takes the
// newer one's.
func TestMergeIntoDatetimeKeptOnlyWhenBothSet(test *testing.T) {
	test.Parallel()

	existing := Payload{Results: []Result{{Source: "s", Flags: []string{"a"}}}}
	newer := Payload{Results: []Result{{Source: "s", Datetime: isoTime(fixedTime), Flags: []string{"a"}}}}

	mergeInto(&existing, newer)

	if !fixedTime.Equal(time.Time(existing.Results[0].Datetime)) {
		test.Errorf("mergeInto() datetime = %v, want %v", time.Time(existing.Results[0].Datetime), fixedTime)
	}
}

// TestMergeIntoCollapsesExistingDuplicates checks that duplicate results already in a file are
// reduced to one, keeping the last.
func TestMergeIntoCollapsesExistingDuplicates(test *testing.T) {
	test.Parallel()

	laterTime := fixedTime.Add(time.Hour)
	existing := Payload{Results: []Result{
		{Source: "s", Datetime: isoTime(fixedTime), Flags: []string{"a", "b"}},
		{Source: "s", Datetime: isoTime(laterTime), Flags: []string{"b", "a"}},
	}}

	mergeInto(&existing, Payload{})

	want := []Result{{Source: "s", Datetime: isoTime(laterTime), Flags: []string{"b", "a"}}}
	if diff := cmp.Diff(want, existing.Results, payloadComparison); "" != diff {
		test.Errorf("mergeInto() results mismatch (-want +got):\n%s", diff)
	}
}

// TestResultKey checks which results count as duplicates.
func TestResultKey(test *testing.T) {
	test.Parallel()

	base := Result{Source: "a", Flags: []string{"x", "y"}}

	testCases := []struct {
		name     string
		other    Result
		wantSame bool
	}{
		{name: "identical", other: Result{Source: "a", Flags: []string{"x", "y"}}, wantSame: true},
		{name: "flag order ignored", other: Result{Source: "a", Flags: []string{"y", "x"}}, wantSame: true},
		{name: "repeated flags ignored", other: Result{Source: "a", Flags: []string{"x", "y", "x"}}, wantSame: true},
		{name: "datetime ignored", other: Result{Source: "a", Flags: []string{"x", "y"}, Datetime: isoTime(fixedTime)}, wantSame: true},
		{name: "metadata ignored", other: Result{Source: "a", Flags: []string{"x", "y"}, Metadata: []byte(`{"k":1}`)}, wantSame: true},
		{name: "different source", other: Result{Source: "b", Flags: []string{"x", "y"}}},
		{name: "different flags", other: Result{Source: "a", Flags: []string{"x"}}},
		// Without a separator, source "ax" with flag "y" would look like source "a" with "x", "y".
		{name: "flag not confused with source", other: Result{Source: "ax", Flags: []string{"y"}}},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if got := resultKey(base) == resultKey(testCase.other); testCase.wantSame != got {
				subtest.Errorf("resultKey(%+v) == resultKey(%+v) is %v, want %v", base, testCase.other, got, testCase.wantSame)
			}
		})
	}
}

// TestResultKeyDoesNotChangeFlags checks that sorting the flags for the key leaves the
// result's own flags alone.
func TestResultKeyDoesNotChangeFlags(test *testing.T) {
	test.Parallel()

	result := Result{Source: "a", Flags: []string{"z", "a", "z"}}
	resultKey(result)

	if want := []string{"z", "a", "z"}; !slices.Equal(want, result.Flags) {
		test.Errorf("resultKey() changed the flags to %v, want %v", result.Flags, want)
	}
}

// TestOnlyDatetimeChanged checks which differences make a file worth rewriting.
func TestOnlyDatetimeChanged(test *testing.T) {
	test.Parallel()

	laterTime := fixedTime.Add(time.Hour)
	base := newTestPayload("1.2.3.4", "s", fixedTime, `{"port": 443, "name": "x"}`, "a")

	testCases := []struct {
		name  string
		after Payload
		want  bool
	}{
		{name: "identical", after: base, want: true},
		{name: "datetime only", after: newTestPayload("1.2.3.4", "s", laterTime, `{"port": 443, "name": "x"}`, "a"), want: true},
		// Files written by Python have their metadata keys in a different order.
		{name: "metadata key order", after: newTestPayload("1.2.3.4", "s", fixedTime, `{"name":"x","port":443}`, "a"), want: true},
		{name: "metadata number format", after: newTestPayload("1.2.3.4", "s", fixedTime, `{"port": 443.0, "name": "x"}`, "a"), want: true},
		{name: "metadata changed", after: newTestPayload("1.2.3.4", "s", fixedTime, `{"port": 80, "name": "x"}`, "a")},
		{name: "invalid metadata", after: newTestPayload("1.2.3.4", "s", fixedTime, `{"port":`, "a")},
		{name: "flags changed", after: Payload{Flags: []string{"a", "b"}, Results: base.Results}},
		{name: "result added", after: newTestPayload("1.2.3.4", "s", fixedTime, `{"port": 443, "name": "x"}`, "a", "b")},
		{name: "source changed", after: newTestPayload("1.2.3.4", "other", fixedTime, `{"port": 443, "name": "x"}`, "a")},
		{name: "result flags changed", after: Payload{Flags: base.Flags, Results: []Result{{Source: "s", Flags: []string{"b"}}}}},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if got := onlyDatetimeChanged(base, testCase.after); testCase.want != got {
				subtest.Errorf("onlyDatetimeChanged(%+v, %+v) = %v, want %v", base, testCase.after, got, testCase.want)
			}
		})
	}
}

// TestClonePayload checks that changing a clone's slices leaves the original alone.
func TestClonePayload(test *testing.T) {
	test.Parallel()

	original := newTestPayload("1.2.3.4", "s", fixedTime, `{}`, "a")
	clone := clonePayload(original)

	clone.Flags[0] = "changed"
	clone.Results[0].Source = "changed"

	if "a" != original.Flags[0] || "s" != original.Results[0].Source {
		test.Errorf("clonePayload() shares slices with the original: %+v", original)
	}
}

// TestWritePayloadErrors checks that metadata that isn't valid JSON is refused rather than
// written.
func TestWritePayloadErrors(test *testing.T) {
	test.Parallel()

	store := newTestStore(test)
	payload := newTestPayload("1.2.3.4", "s", fixedTime, `{"port":`, "a")

	if err := writePayload(store.root, "payload.json", payload); nil == err {
		test.Error("writePayload() with invalid metadata error = nil, want error")
	}

	if _, err := store.root.Stat("payload.json"); !errors.Is(err, fs.ErrNotExist) {
		test.Errorf("writePayload() left a file behind: stat error = %v", err)
	}
}

// TestWriteFileAtomically checks that a file is replaced whole, with no temporary file left
// behind.
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

// TestWriteFileAtomicallyErrors checks that failed writes are reported, that their temporary
// files are cleaned up, and that a temporary file that can't be removed is reported too.
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

// prepareOutputDirectory runs prepare, if it's set, on the store's output directory.
func prepareOutputDirectory(testingContext testing.TB, store *Store, prepare func(root *os.Root) error) {
	testingContext.Helper()

	if nil == prepare {
		return
	}

	if err := prepare(store.root); nil != err {
		testingContext.Fatalf("preparing output directory: %v", err)
	}
}
