package extractors

import "testing"

func TestViriBackTracker(t *testing.T) {
	body := "Family,URL,IP,FirstSeen\n" +
		"Cobalt Strike,http://1.2.3.4/login.php,1.2.3.4,19-05-2026\n" +
		"AgentTesla,http://5.6.7.8/,5.6.7.8,1-2-2026\n"

	payloads, err := ViriBackTracker(body)
	if nil != err {
		t.Fatal(err)
	}
	if 2 != len(payloads) {
		t.Fatalf("len(payloads) = %d, want 2", len(payloads))
	}

	r := assertSingleResult(t, payloads[0], "1.2.3.4", "viribacktracker", "cobalt strike")
	if "2026-05-19T00:00:00" != r.Metadata["firstSeen"] {
		t.Errorf("firstSeen = %v", r.Metadata["firstSeen"])
	}
	if "http://1.2.3.4/login.php" != r.Metadata["login"] {
		t.Errorf("login = %v", r.Metadata["login"])
	}

	// Unpadded day and month are accepted, as with strptime
	r = assertSingleResult(t, payloads[1], "5.6.7.8", "viribacktracker", "agenttesla")
	if "2026-02-01T00:00:00" != r.Metadata["firstSeen"] {
		t.Errorf("firstSeen = %v", r.Metadata["firstSeen"])
	}
}

func TestViriBackTrackerErrors(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"bad date", "header\nfam,login,1.2.3.4,2026-05-19\n"},
		{"wrong column count", "header\nfam,1.2.3.4,19-05-2026\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ViriBackTracker(tt.body); nil == err {
				t.Error("ViriBackTracker() error = nil, want error")
			}
		})
	}
}
