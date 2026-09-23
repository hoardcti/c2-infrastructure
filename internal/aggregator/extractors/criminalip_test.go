package extractors

import "testing"

func TestCriminalIP(t *testing.T) {
	body := "IP,flag,port,score,country,scanTime\r\n" +
		"1.2.3.4,Cobalt Strike,443,Critical,US,2026-05-19 01:00:00\r\n" +
		"5.6.7.8,Metasploit,80,Dangerous,DE,2026-05-19 02:00:00\r\n"

	payloads, err := CriminalIP(body)
	if nil != err {
		t.Fatal(err)
	}
	if 2 != len(payloads) {
		t.Fatalf("len(payloads) = %d, want 2", len(payloads))
	}

	r := assertSingleResult(t, payloads[0], "1.2.3.4", "criminalip", "cobalt strike")

	want := map[string]string{"port": "443", "score": "Critical", "country": "US", "scanTime": "2026-05-19 01:00:00"}
	for key, value := range want {
		if value != r.Metadata[key] {
			t.Errorf("metadata[%q] = %v, want %q", key, r.Metadata[key], value)
		}
	}

	assertSingleResult(t, payloads[1], "5.6.7.8", "criminalip", "metasploit")
}

func TestCriminalIPHeaderOnly(t *testing.T) {
	payloads, err := CriminalIP("IP,flag,port,score,country,scanTime\n")
	if nil != err {
		t.Fatal(err)
	}
	if 0 != len(payloads) {
		t.Errorf("len(payloads) = %d, want 0", len(payloads))
	}
}

func TestCriminalIPWrongColumnCount(t *testing.T) {
	if _, err := CriminalIP("header\n1.2.3.4,flag,443\n"); nil == err {
		t.Error("CriminalIP() error = nil, want error for short row")
	}
}
