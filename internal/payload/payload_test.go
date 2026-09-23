package payload

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"
)

func TestISOFormat(t *testing.T) {
	tests := []struct {
		name string
		in   time.Time
		want string
	}{
		{"whole seconds", time.Date(2026, 5, 19, 1, 2, 3, 0, time.UTC), "2026-05-19T01:02:03"},
		{"microseconds", time.Date(2026, 5, 19, 1, 2, 3, 123456000, time.UTC), "2026-05-19T01:02:03.123456"},
		{"sub-microsecond truncated", time.Date(2026, 5, 19, 1, 2, 3, 999, time.UTC), "2026-05-19T01:02:03"},
		{"leading zero micros", time.Date(2026, 5, 19, 1, 2, 3, 1000, time.UTC), "2026-05-19T01:02:03.000001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ISOFormat(tt.in); tt.want != got {
				t.Errorf("ISOFormat() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNow(t *testing.T) {
	re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{6})?$`)

	if got := Now(); false == re.MatchString(got) {
		t.Errorf("Now() = %q, not in isoformat", got)
	}
}

func TestPayloadJSONShape(t *testing.T) {
	p := Payload{
		IP:    "1.2.3.4",
		Flags: []string{"cobalt strike"},
		Results: []Result{{
			Source:   "test",
			Datetime: "2026-05-19T00:00:00",
			Flags:    []string{"cobalt strike"},
			Metadata: map[string]any{"port": "443"},
		}},
	}

	got, err := json.Marshal(p)
	if nil != err {
		t.Fatal(err)
	}

	want := `{"ip":"1.2.3.4","flags":["cobalt strike"],"results":[{"source":"test","datetime":"2026-05-19T00:00:00","flags":["cobalt strike"],"metadata":{"port":"443"}}]}`
	if want != string(got) {
		t.Errorf("json = %s\nwant   %s", got, want)
	}
}
