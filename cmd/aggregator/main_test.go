package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); nil != err {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	sources := filepath.Join(dir, "sources.json")
	env := filepath.Join(dir, ".env")

	writeFile(t, sources, `{"aggregator": {}}`)
	writeFile(t, env, "AGGREGATOR_MAIN_TEST=loaded\n")

	t.Setenv("AGGREGATOR_MAIN_TEST", "")
	os.Unsetenv("AGGREGATOR_MAIN_TEST")

	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-sources", sources, "-out", filepath.Join(dir, "out"), "-env", env}, &stderr)

	if 0 != code {
		t.Errorf("run() = %d, want 0; stderr: %s", code, &stderr)
	}
	if got := os.Getenv("AGGREGATOR_MAIN_TEST"); "loaded" != got {
		t.Errorf("env from .env = %q, want %q", got, "loaded")
	}
}

func TestRunMissingSources(t *testing.T) {
	dir := t.TempDir()

	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-sources", filepath.Join(dir, "missing.json"), "-env", filepath.Join(dir, ".env")}, &stderr)

	if 1 != code {
		t.Errorf("run() = %d, want 1", code)
	}
	if false == strings.Contains(stderr.String(), "Failed to load sources") {
		t.Errorf("stderr = %q, want load failure", &stderr)
	}
}

func TestRunBadEnvFile(t *testing.T) {
	dir := t.TempDir()

	// A directory cannot be read as a .env file
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"-env", dir}, &stderr)

	if 1 != code {
		t.Errorf("run() = %d, want 1", code)
	}
}

func TestRunBadFlag(t *testing.T) {
	var stderr bytes.Buffer

	if code := run(context.Background(), []string{"-nope"}, &stderr); 2 != code {
		t.Errorf("run() = %d, want 2", code)
	}
}
