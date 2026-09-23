package extractors

import (
	"regexp"
	"testing"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

// isoFormat matches the output of payload.ISOFormat.
var isoFormat = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?$`)

// assertSingleResult checks the fields every extractor sets identically.
func assertSingleResult(t *testing.T, p payload.Payload, ip, source, flag string) payload.Result {
	t.Helper()

	if ip != p.IP {
		t.Errorf("ip = %q, want %q", p.IP, ip)
	}
	if 1 != len(p.Flags) || flag != p.Flags[0] {
		t.Errorf("flags = %v, want [%s]", p.Flags, flag)
	}
	if 1 != len(p.Results) {
		t.Fatalf("len(results) = %d, want 1", len(p.Results))
	}

	r := p.Results[0]
	if source != r.Source {
		t.Errorf("source = %q, want %q", r.Source, source)
	}
	if 1 != len(r.Flags) || flag != r.Flags[0] {
		t.Errorf("result flags = %v, want [%s]", r.Flags, flag)
	}
	if false == isoFormat.MatchString(r.Datetime) {
		t.Errorf("datetime = %q, not isoformat", r.Datetime)
	}

	return r
}

func TestSkipFirstLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"lf", "h\na\nb", "a\nb"},
		{"crlf", "h\r\na\r\nb", "a\r\nb"},
		{"cr", "h\ra", "a"},
		{"header only", "header", ""},
		{"header with newline", "header\n", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := skipFirstLine(tt.in); tt.want != got {
				t.Errorf("skipFirstLine(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestReadCSVRows(t *testing.T) {
	rows, err := readCSVRows("a,b\n1,2\n\"x,y\",z\n", 2)
	if nil != err {
		t.Fatal(err)
	}

	if 2 != len(rows) || "1" != rows[0][0] || "x,y" != rows[1][0] {
		t.Errorf("rows = %q", rows)
	}

	if _, err := readCSVRows("a,b\n1,2,3\n", 2); nil == err {
		t.Error("readCSVRows with wrong field count error = nil, want error")
	}
}

func TestRequireKeys(t *testing.T) {
	obj := map[string]any{"a": 1, "b": nil}

	if err := requireKeys(obj, "a", "b"); nil != err {
		t.Errorf("requireKeys() error = %v, want nil (null values count as present)", err)
	}
	if err := requireKeys(obj, "a", "c"); nil == err {
		t.Error("requireKeys() error = nil, want error for missing key")
	}
}

func TestStringField(t *testing.T) {
	obj := map[string]any{"s": "value", "n": 1.0}

	if got, err := stringField(obj, "s"); nil != err || "value" != got {
		t.Errorf("stringField(s) = (%q, %v)", got, err)
	}
	if _, err := stringField(obj, "n"); nil == err {
		t.Error("stringField(n) error = nil, want error for non-string")
	}
	if _, err := stringField(obj, "missing"); nil == err {
		t.Error("stringField(missing) error = nil, want error")
	}
}

func TestGetOr(t *testing.T) {
	obj := map[string]any{"present": "v", "null": nil}

	if got := getOr(obj, "present", "def"); "v" != got {
		t.Errorf("getOr(present) = %v", got)
	}
	if got := getOr(obj, "null", "def"); nil != got {
		t.Errorf("getOr(null) = %v, want nil", got)
	}
	if got := getOr(obj, "missing", "def"); "def" != got {
		t.Errorf("getOr(missing) = %v, want def", got)
	}
}
