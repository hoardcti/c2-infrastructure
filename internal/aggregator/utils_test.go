package aggregator

import (
	"testing"

	"github.com/doodad-labs/command-server-watch/internal/payload"
)

func TestResultKey(t *testing.T) {
	base := payload.Result{Source: "a", Flags: []string{"x", "y"}}

	tests := []struct {
		name  string
		other payload.Result
		same  bool
	}{
		{"identical", payload.Result{Source: "a", Flags: []string{"x", "y"}}, true},
		{"flag order ignored", payload.Result{Source: "a", Flags: []string{"y", "x"}}, true},
		{"duplicate flags ignored", payload.Result{Source: "a", Flags: []string{"x", "y", "x"}}, true},
		{"datetime ignored", payload.Result{Source: "a", Flags: []string{"x", "y"}, Datetime: "later"}, true},
		{"metadata ignored", payload.Result{Source: "a", Flags: []string{"x", "y"}, Metadata: map[string]any{"k": 1}}, true},
		{"different source", payload.Result{Source: "b", Flags: []string{"x", "y"}}, false},
		{"different flags", payload.Result{Source: "a", Flags: []string{"x"}}, false},
		{"flag not confused with source", payload.Result{Source: "ax", Flags: []string{"y"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resultKey(base) == resultKey(tt.other)
			if tt.same != got {
				t.Errorf("keys equal = %v, want %v", got, tt.same)
			}
		})
	}
}

func TestResultKeyDoesNotMutateFlags(t *testing.T) {
	r := payload.Result{Source: "a", Flags: []string{"z", "a", "z"}}
	resultKey(r)

	if "z" != r.Flags[0] || "a" != r.Flags[1] || "z" != r.Flags[2] {
		t.Errorf("resultKey mutated flags: %v", r.Flags)
	}
}

func TestValidIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.1", true},
		{"0.0.0.0", true},
		{"2001:db8::1", true},
		{"::ffff:1.2.3.4", true},
		{"", false},
		{"256.1.1.1", false},
		{"192.168.01.1", false},
		{"1.2.3", false},
		{"not-an-ip", false},
		{"1.2.3.4:80", false},
		{"fe80::1%eth0", false},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := validIP(tt.ip); tt.want != got {
				t.Errorf("validIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
