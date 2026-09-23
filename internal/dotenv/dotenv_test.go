package dotenv

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		line      string
		wantKey   string
		wantValue string
		wantOK    bool
	}{
		{`FOO=bar`, "FOO", "bar", true},
		{`  FOO = bar  `, "FOO", "bar", true},
		{`FOO=""`, "FOO", "", true},
		{`FOO="quoted value"`, "FOO", "quoted value", true},
		{`FOO='single # not comment'`, "FOO", "single # not comment", true},
		{`FOO=bar # trailing comment`, "FOO", "bar", true},
		{`export FOO=bar`, "FOO", "bar", true},
		{`FOO=a=b`, "FOO", "a=b", true},
		{``, "", "", false},
		{`# comment`, "", "", false},
		{`NOEQUALS`, "", "", false},
		{`=value`, "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			key, value, ok := parseLine(tt.line)
			if tt.wantOK != ok || tt.wantKey != key || tt.wantValue != value {
				t.Errorf("parseLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.line, key, value, ok, tt.wantKey, tt.wantValue, tt.wantOK)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	content := "# keys\nDOTENV_TEST_NEW=\"from file\"\nDOTENV_TEST_EXISTING=from file\n"
	if err := os.WriteFile(path, []byte(content), 0o600); nil != err {
		t.Fatal(err)
	}

	t.Setenv("DOTENV_TEST_EXISTING", "from env")
	// Register cleanup for the key Load will set, then clear it
	t.Setenv("DOTENV_TEST_NEW", "")
	os.Unsetenv("DOTENV_TEST_NEW")

	if err := Load(path); nil != err {
		t.Fatalf("Load() error = %v", err)
	}

	if got := os.Getenv("DOTENV_TEST_NEW"); "from file" != got {
		t.Errorf("DOTENV_TEST_NEW = %q, want %q", got, "from file")
	}

	if got := os.Getenv("DOTENV_TEST_EXISTING"); "from env" != got {
		t.Errorf("DOTENV_TEST_EXISTING = %q, want existing value to be kept", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if err := Load(filepath.Join(t.TempDir(), "missing.env")); nil != err {
		t.Errorf("Load() on missing file error = %v, want nil", err)
	}
}

func TestLoadUnreadable(t *testing.T) {
	// A directory cannot be scanned as a file
	if err := Load(t.TempDir()); nil == err {
		t.Error("Load() on a directory error = nil, want error")
	}
}
