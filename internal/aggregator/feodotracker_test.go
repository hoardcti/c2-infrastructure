package extractors

import "testing"

func TestFeodoTracker(t *testing.T) {
	body := `[
		{
			"ip_address": "1.2.3.4",
			"port": 443,
			"status": "online",
			"hostname": null,
			"country": "US",
			"first_seen": "2026-01-01 00:00:00",
			"last_online": "2026-05-19",
			"malware": "QakBot"
		}
	]`

	payloads, err := FeodoTracker(body)
	if nil != err {
		t.Fatal(err)
	}
	if 1 != len(payloads) {
		t.Fatalf("len(payloads) = %d, want 1", len(payloads))
	}

	r := assertSingleResult(t, payloads[0], "1.2.3.4", "feodotracker", "qakbot")

	if "US" != r.Metadata["country"] {
		t.Errorf("country = %v", r.Metadata["country"])
	}
	if "2026-01-01 00:00:00" != r.Metadata["firstSeen"] {
		t.Errorf("firstSeen = %v", r.Metadata["firstSeen"])
	}
	if "2026-05-19" != r.Metadata["lastOnline"] {
		t.Errorf("lastOnline = %v", r.Metadata["lastOnline"])
	}
	if hostname, ok := r.Metadata["hostname"]; false == ok || nil != hostname {
		t.Errorf("hostname = %v (present %v), want null", hostname, ok)
	}
	if float64(443) != r.Metadata["port"] {
		t.Errorf("port = %v, want 443", r.Metadata["port"])
	}
	if _, ok := r.Metadata["status"]; ok {
		t.Error("unexpected status field copied into metadata")
	}
}

func TestFeodoTrackerEmpty(t *testing.T) {
	payloads, err := FeodoTracker("[]")
	if nil != err {
		t.Fatal(err)
	}
	if 0 != len(payloads) {
		t.Errorf("len(payloads) = %d, want 0", len(payloads))
	}
}

func TestFeodoTrackerErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"invalid json", "{"},
		{"not a list", `{"ip_address": "1.2.3.4"}`},
		{"missing key", `[{"ip_address": "1.2.3.4", "malware": "x"}]`},
		{"non-string malware", `[{"ip_address": "1.2.3.4", "malware": 1, "country": "", "first_seen": "", "last_online": "", "hostname": null, "port": 1}]`},
		{"non-string ip", `[{"ip_address": 1, "malware": "x", "country": "", "first_seen": "", "last_online": "", "hostname": null, "port": 1}]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FeodoTracker(tt.body); nil == err {
				t.Error("FeodoTracker() error = nil, want error")
			}
		})
	}
}
