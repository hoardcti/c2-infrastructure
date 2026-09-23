package aggregator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

func newResult(source, datetime string, flags []string, metadata map[string]any) payload.Result {
	return payload.Result{Source: source, Datetime: datetime, Flags: flags, Metadata: metadata}
}

func readPayload(t *testing.T, path string) payload.Payload {
	t.Helper()

	data, err := os.ReadFile(path)
	if nil != err {
		t.Fatal(err)
	}

	var p payload.Payload
	if err := json.Unmarshal(data, &p); nil != err {
		t.Fatal(err)
	}

	return p
}

func TestValidatePayload(t *testing.T) {
	tests := []struct {
		name string
		p    payload.Payload
		want bool
	}{
		{"valid", payload.Payload{IP: "1.2.3.4", Flags: []string{}, Results: []payload.Result{}}, true},
		{"nil flags", payload.Payload{IP: "1.2.3.4", Results: []payload.Result{}}, false},
		{"nil results", payload.Payload{IP: "1.2.3.4", Flags: []string{}}, false},
		{"bad ip", payload.Payload{IP: "nope", Flags: []string{}, Results: []payload.Result{}}, false},
		{"empty ip", payload.Payload{Flags: []string{}, Results: []payload.Result{}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validatePayload(tt.p); tt.want != got {
				t.Errorf("validatePayload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPToPath(t *testing.T) {
	s := &Store{Dir: "root"}

	tests := []struct {
		ip   string
		want string
	}{
		{"192.168.1.1", filepath.Join("root", "ipv4", "192", "168", "1", "1.json")},
		{"2001:db8:85a3::8a2e:370:7334", filepath.Join("root", "ipv6", "2001", "0db8", "85a3", "0000", "0000", "8a2e", "0370", "7334.json")},
		{"::1", filepath.Join("root", "ipv6", "0000", "0000", "0000", "0000", "0000", "0000", "0000", "0001.json")},
		{"::ffff:1.2.3.4", filepath.Join("root", "ipv6", "0000", "0000", "0000", "0000", "0000", "ffff", "0102", "0304.json")},
		{"2001:DB8::ABCD", filepath.Join("root", "ipv6", "2001", "0db8", "0000", "0000", "0000", "0000", "0000", "abcd.json")},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			got, err := s.ipToPath(tt.ip)
			if nil != err {
				t.Fatal(err)
			}
			if tt.want != got {
				t.Errorf("ipToPath(%q) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}

	if _, err := s.ipToPath("bogus"); nil == err {
		t.Error("ipToPath(bogus) error = nil, want error")
	}
}

func TestMergeInto(t *testing.T) {
	existing := payload.Payload{
		IP:    "1.2.3.4",
		Flags: []string{"b", "a"},
		Results: []payload.Result{
			newResult("s1", "old", []string{"a"}, map[string]any{"v": "1"}),
			newResult("s2", "old2", []string{"b"}, nil),
		},
	}
	newer := payload.Payload{
		IP:    "1.2.3.4",
		Flags: []string{"c", "a"},
		Results: []payload.Result{
			newResult("s1", "new", []string{"a"}, map[string]any{"v": "2"}),
			newResult("s3", "new3", []string{"c"}, nil),
		},
	}

	mergeInto(&existing, newer)

	if want := []string{"a", "b", "c"}; false == slices.Equal(want, existing.Flags) {
		t.Errorf("flags = %v, want %v", existing.Flags, want)
	}

	if 3 != len(existing.Results) {
		t.Fatalf("len(results) = %d, want 3", len(existing.Results))
	}

	first := existing.Results[0]
	if "s1" != first.Source || "old" != first.Datetime || "2" != first.Metadata["v"] {
		t.Errorf("duplicate result = %+v, want new metadata with original datetime", first)
	}

	if "s2" != existing.Results[1].Source || "s3" != existing.Results[2].Source {
		t.Errorf("result order = %s, %s; want s2, s3", existing.Results[1].Source, existing.Results[2].Source)
	}

	if "new" != newer.Results[0].Datetime {
		t.Errorf("mergeInto mutated the incoming payload")
	}
}

func TestMergeIntoDatetimeOnlyPreservedWhenBothSet(t *testing.T) {
	existing := payload.Payload{Results: []payload.Result{newResult("s", "", []string{"a"}, nil)}}
	newer := payload.Payload{Results: []payload.Result{newResult("s", "new", []string{"a"}, nil)}}

	mergeInto(&existing, newer)

	if "new" != existing.Results[0].Datetime {
		t.Errorf("datetime = %q, want %q", existing.Results[0].Datetime, "new")
	}
}

func TestMergeIntoCollapsesExistingDuplicates(t *testing.T) {
	existing := payload.Payload{Results: []payload.Result{
		newResult("s", "first", []string{"a", "b"}, nil),
		newResult("s", "second", []string{"b", "a"}, nil),
	}}

	mergeInto(&existing, payload.Payload{})

	if 1 != len(existing.Results) || "second" != existing.Results[0].Datetime {
		t.Errorf("results = %+v, want single entry keeping the last duplicate", existing.Results)
	}
}

func TestOnlyDatetimeChanged(t *testing.T) {
	base := payload.Payload{
		Flags:   []string{"a"},
		Results: []payload.Result{newResult("s", "t1", []string{"a"}, map[string]any{"port": float64(443)})},
	}

	tests := []struct {
		name  string
		after payload.Payload
		want  bool
	}{
		{"identical", base, true},
		{"datetime only", payload.Payload{
			Flags:   []string{"a"},
			Results: []payload.Result{newResult("s", "t2", []string{"a"}, map[string]any{"port": float64(443)})},
		}, true},
		{"int vs float metadata", payload.Payload{
			Flags:   []string{"a"},
			Results: []payload.Result{newResult("s", "t1", []string{"a"}, map[string]any{"port": 443})},
		}, true},
		{"flags changed", payload.Payload{
			Flags:   []string{"a", "b"},
			Results: base.Results,
		}, false},
		{"result added", payload.Payload{
			Flags:   []string{"a"},
			Results: append(slices.Clone(base.Results), newResult("x", "t", nil, nil)),
		}, false},
		{"metadata changed", payload.Payload{
			Flags:   []string{"a"},
			Results: []payload.Result{newResult("s", "t1", []string{"a"}, map[string]any{"port": 80})},
		}, false},
		{"source changed", payload.Payload{
			Flags:   []string{"a"},
			Results: []payload.Result{newResult("z", "t1", []string{"a"}, map[string]any{"port": 443})},
		}, false},
		{"result flags changed", payload.Payload{
			Flags:   []string{"a"},
			Results: []payload.Result{newResult("s", "t1", []string{"b"}, map[string]any{"port": 443})},
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := onlyDatetimeChanged(base, tt.after); tt.want != got {
				t.Errorf("onlyDatetimeChanged() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClonePayload(t *testing.T) {
	p := payload.Payload{IP: "1.2.3.4", Flags: []string{"a"}, Results: []payload.Result{newResult("s", "t", nil, nil)}}
	c := clonePayload(p)

	c.Flags[0] = "changed"
	c.Results[0].Source = "changed"

	if "a" != p.Flags[0] || "s" != p.Results[0].Source {
		t.Errorf("clonePayload shares slices with the original: %+v", p)
	}
}

func TestWriteJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.json")

	if err := writeJSON(path, map[string]any{"url": "http://x/?a=1&b=<2>"}); nil != err {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if nil != err {
		t.Fatal(err)
	}

	want := "{\n    \"url\": \"http://x/?a=1&b=<2>\"\n}\n"
	if want != string(got) {
		t.Errorf("file = %q, want %q", got, want)
	}
}

func TestSavePayloadNewFile(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	p := payload.Payload{
		IP:      "10.0.0.1",
		Flags:   []string{"z", "a"},
		Results: []payload.Result{newResult("s", "t", []string{"z", "a"}, map[string]any{"k": "v"})},
	}

	if err := s.SavePayload(p); nil != err {
		t.Fatal(err)
	}

	got := readPayload(t, filepath.Join(s.Dir, "ipv4", "10", "0", "0", "1.json"))

	// First write stores the payload as-is, without sorting flags
	if "10.0.0.1" != got.IP || false == slices.Equal([]string{"z", "a"}, got.Flags) || 1 != len(got.Results) {
		t.Errorf("stored payload = %+v", got)
	}
}

func TestSavePayloadMerges(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	path := filepath.Join(s.Dir, "ipv4", "10", "0", "0", "1.json")

	first := payload.Payload{IP: "10.0.0.1", Flags: []string{"a"}, Results: []payload.Result{newResult("s1", "t1", []string{"a"}, nil)}}
	second := payload.Payload{IP: "10.0.0.1", Flags: []string{"b"}, Results: []payload.Result{newResult("s2", "t2", []string{"b"}, nil)}}

	if err := s.SavePayload(first); nil != err {
		t.Fatal(err)
	}
	if err := s.SavePayload(second); nil != err {
		t.Fatal(err)
	}

	got := readPayload(t, path)
	if false == slices.Equal([]string{"a", "b"}, got.Flags) || 2 != len(got.Results) {
		t.Errorf("merged payload = %+v", got)
	}
}

func TestSavePayloadSkipsDatetimeOnlyChange(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	path := filepath.Join(s.Dir, "ipv4", "10", "0", "0", "1.json")

	p := payload.Payload{IP: "10.0.0.1", Flags: []string{"a"}, Results: []payload.Result{newResult("s", "t1", []string{"a"}, map[string]any{"port": 443})}}
	if err := s.SavePayload(p); nil != err {
		t.Fatal(err)
	}

	// Backdate the file so any rewrite is detectable via mtime
	past := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(path, past, past); nil != err {
		t.Fatal(err)
	}

	p.Results = []payload.Result{newResult("s", "t2", []string{"a"}, map[string]any{"port": 443})}
	if err := s.SavePayload(p); nil != err {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if nil != err {
		t.Fatal(err)
	}
	if false == info.ModTime().Equal(past) {
		t.Error("file was rewritten for a datetime-only change")
	}

	if got := readPayload(t, path); "t1" != got.Results[0].Datetime {
		t.Errorf("datetime = %q, want original %q", got.Results[0].Datetime, "t1")
	}
}

func TestSavePayloadIgnoresInvalid(t *testing.T) {
	s := &Store{Dir: t.TempDir()}

	if err := s.SavePayload(payload.Payload{IP: "not-an-ip", Flags: []string{}, Results: []payload.Result{}}); nil != err {
		t.Fatalf("SavePayload(invalid) error = %v, want nil", err)
	}

	entries, err := os.ReadDir(s.Dir)
	if nil != err {
		t.Fatal(err)
	}
	if 0 != len(entries) {
		t.Errorf("invalid payload created files: %v", entries)
	}
}

func TestSavePayloadCorruptExisting(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	path := filepath.Join(s.Dir, "ipv4", "10", "0", "0", "1.json")

	if err := os.MkdirAll(filepath.Dir(path), 0o755); nil != err {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); nil != err {
		t.Fatal(err)
	}

	p := payload.Payload{IP: "10.0.0.1", Flags: []string{}, Results: []payload.Result{}}
	if err := s.SavePayload(p); nil == err {
		t.Error("SavePayload over corrupt file error = nil, want error")
	}
}
