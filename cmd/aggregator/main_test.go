package main

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

// DISABLED_SOURCES is a sources file whose only source is disabled.
const DISABLED_SOURCES = `{"aggregator": {"api": [{"name": "threatfox", "enabled": false}]}}`

// UNREACHABLE_THREATFOX_SOURCES enables ThreatFox at an address nothing listens on, so the run
// fails at run time rather than while checking the configuration.
const UNREACHABLE_THREATFOX_SOURCES = `{"aggregator": {"api": [{
	"name": "threatfox",
	"enabled": true,
	"url": "https://127.0.0.1:1/api/v1/",
	"query": {"query": "taginfo", "limit": 1}
}]}}`

// TestRunWithNoEnabledSources checks a successful run: it reports on stdout, logs to stderr and
// creates the output directory.
func TestRunWithNoEnabledSources(test *testing.T) {
	test.Parallel()

	directory := test.TempDir()
	outputDirectory := filepath.Join(directory, "out")
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", DISABLED_SOURCES),
		"-out", outputDirectory,
		"-env", filepath.Join(directory, "missing.env"),
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_SUCCESS != exitCode {
		test.Fatalf("run(%q) = %d, want %d; stderr: %s", arguments, exitCode, EXIT_SUCCESS, &stderr)
	}

	if "stored 0 payloads\n" != stdout.String() {
		test.Errorf("run(%q) stdout = %q, want %q", arguments, &stdout, "stored 0 payloads\n")
	}

	if !strings.Contains(stderr.String(), `msg="aggregation finished"`) {
		test.Errorf("run(%q) stderr = %q, want the finished message", arguments, &stderr)
	}

	if info, err := os.Stat(outputDirectory); nil != err || !info.IsDir() {
		test.Errorf("run(%q) didn't create the output directory: %v", arguments, err)
	}
}

// TestRunLogsJSON checks that -log json writes one JSON object per line, and that -level
// filters the messages.
func TestRunLogsJSON(test *testing.T) {
	test.Parallel()

	directory := test.TempDir()
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", DISABLED_SOURCES),
		"-out", filepath.Join(directory, "out"),
		"-env", filepath.Join(directory, "missing.env"),
		"-log", "json",
		"-level", "warn",
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_SUCCESS != exitCode {
		test.Fatalf("run(%q) = %d, want %d; stderr: %s", arguments, exitCode, EXIT_SUCCESS, &stderr)
	}

	// Only information messages are logged by a successful run, and -level warn hides them.
	if 0 != stderr.Len() {
		test.Errorf("run(%q) stderr = %q, want nothing at warn level", arguments, &stderr)
	}
}

// TestRunFailsWhenASourceFails checks that a runtime failure is logged once as JSON, without
// the API key, and returns EXIT_FAILURE. It doesn't run in parallel because it changes the
// process environment.
func TestRunFailsWhenASourceFails(test *testing.T) {
	test.Setenv(ABUSECH_API_KEY_VARIABLE, "secret-test-key")

	directory := test.TempDir()
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", UNREACHABLE_THREATFOX_SOURCES),
		"-out", filepath.Join(directory, "out"),
		"-env", filepath.Join(directory, "missing.env"),
		"-log", "json",
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_FAILURE != exitCode {
		test.Fatalf("run(%q) = %d, want %d; stderr: %s", arguments, exitCode, EXIT_FAILURE, &stderr)
	}

	if "stored 0 payloads\n" != stdout.String() {
		test.Errorf("run(%q) stdout = %q, want %q", arguments, &stdout, "stored 0 payloads\n")
	}

	// Every line is a JSON log entry; the failure is logged exactly once.
	failureCount := 0

	for line := range strings.Lines(stderr.String()) {
		// The struct tag names the JSON key the field is read from.
		var entry struct {
			// Message is the log message.
			Message string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &entry); nil != err {
			test.Errorf("stderr line %q isn't JSON: %v", line, err)
		}

		if "aggregation failed" == entry.Message {
			failureCount++
		}
	}

	if 1 != failureCount {
		test.Errorf("run(%q) logged the failure %d times, want once; stderr: %s", arguments, failureCount, &stderr)
	}

	if strings.Contains(stderr.String(), "secret-test-key") {
		test.Errorf("run(%q) stderr = %q, want the API key kept out of the logs", arguments, &stderr)
	}
}

// TestRunLoadsEnvFile checks that the .env file supplies ABUSECH_API_KEY when the environment
// doesn't. It doesn't run in parallel because it changes the process environment.
func TestRunLoadsEnvFile(test *testing.T) {
	// Setenv restores the variable when the test ends; it's then removed, because an empty
	// variable still counts as set and would stop the .env file supplying it.
	test.Setenv(ABUSECH_API_KEY_VARIABLE, "")

	if err := os.Unsetenv(ABUSECH_API_KEY_VARIABLE); nil != err {
		test.Fatalf("unsetting %s: %v", ABUSECH_API_KEY_VARIABLE, err)
	}

	directory := test.TempDir()
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", UNREACHABLE_THREATFOX_SOURCES),
		"-out", filepath.Join(directory, "out"),
		"-env", writeTestFile(test, directory, ".env", "# abuse.ch key\nABUSECH_API_KEY=\"from-env-file\"\n"),
	}

	// With the key loaded, the configuration is valid and the run gets as far as the network.
	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_FAILURE != exitCode {
		test.Errorf("run(%q) = %d, want %d; stderr: %s", arguments, exitCode, EXIT_FAILURE, &stderr)
	}

	if "from-env-file" != os.Getenv(ABUSECH_API_KEY_VARIABLE) {
		test.Errorf("%s = %q after run, want the value from the .env file", ABUSECH_API_KEY_VARIABLE, os.Getenv(ABUSECH_API_KEY_VARIABLE))
	}
}

// TestRunEnvironmentOverridesEnvFile checks that a variable already set in the environment
// wins over the .env file. It doesn't run in parallel because it changes the process
// environment.
func TestRunEnvironmentOverridesEnvFile(test *testing.T) {
	test.Setenv(ABUSECH_API_KEY_VARIABLE, "from-environment")

	directory := test.TempDir()
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", DISABLED_SOURCES),
		"-out", filepath.Join(directory, "out"),
		"-env", writeTestFile(test, directory, ".env", "ABUSECH_API_KEY=from-env-file\n"),
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_SUCCESS != exitCode {
		test.Fatalf("run(%q) = %d, want %d; stderr: %s", arguments, exitCode, EXIT_SUCCESS, &stderr)
	}

	if "from-environment" != os.Getenv(ABUSECH_API_KEY_VARIABLE) {
		test.Errorf("%s = %q after run, want the environment's value kept", ABUSECH_API_KEY_VARIABLE, os.Getenv(ABUSECH_API_KEY_VARIABLE))
	}
}

// TestRunMissingAPIKey checks that an enabled ThreatFox source without a key is a usage error.
// It doesn't run in parallel because it changes the process environment.
func TestRunMissingAPIKey(test *testing.T) {
	test.Setenv(ABUSECH_API_KEY_VARIABLE, "")

	directory := test.TempDir()
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", UNREACHABLE_THREATFOX_SOURCES),
		"-out", filepath.Join(directory, "out"),
		"-env", filepath.Join(directory, "missing.env"),
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_USAGE != exitCode {
		test.Errorf("run(%q) = %d, want %d", arguments, exitCode, EXIT_USAGE)
	}

	if !strings.Contains(stderr.String(), "ABUSECH_API_KEY") {
		test.Errorf("run(%q) stderr = %q, want it to name ABUSECH_API_KEY", arguments, &stderr)
	}
}

// TestRunUsageErrors checks that bad flags, arguments, .env files and sources files are usage
// errors, reported before any work starts.
func TestRunUsageErrors(test *testing.T) {
	test.Parallel()

	directory := test.TempDir()
	missingEnvFile := filepath.Join(directory, "missing.env")

	testCases := []struct {
		name      string
		arguments []string
		// wantStderr is part of the message stderr must contain.
		wantStderr string
	}{
		{name: "unknown flag", arguments: []string{"-nope"}, wantStderr: "flag provided but not defined"},
		{name: "extra argument", arguments: []string{"-env", missingEnvFile, "extra"}, wantStderr: "unexpected arguments"},
		{name: "unknown log format", arguments: []string{"-env", missingEnvFile, "-log", "xml"}, wantStderr: `unknown log format "xml"`},
		{name: "unknown log level", arguments: []string{"-env", missingEnvFile, "-level", "loud"}, wantStderr: "-level"},
		// A directory can't be read as a .env file.
		{name: "unreadable env file", arguments: []string{"-env", directory}, wantStderr: "loading"},
		{
			name:       "missing sources file",
			arguments:  []string{"-env", missingEnvFile, "-sources", filepath.Join(directory, "missing.json")},
			wantStderr: "loading sources failed",
		},
		{
			name:       "invalid sources",
			arguments:  []string{"-env", missingEnvFile, "-out", filepath.Join(directory, "out"), "-sources", writeTestFile(test, directory, "invalid.json", `{"aggregator": {"json": [{"name": "unknown", "enabled": true}]}}`)},
			wantStderr: "checking sources failed",
		},
	}

	for _, testCase := range testCases {
		// The function literal is a closure over testCase. Each loop iteration has its own
		// testCase, so the parallel subtests never share one.
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			var stdout, stderr bytes.Buffer
			if exitCode := run(subtest.Context(), testCase.arguments, &stdout, &stderr); EXIT_USAGE != exitCode {
				subtest.Errorf("run(%q) = %d, want %d", testCase.arguments, exitCode, EXIT_USAGE)
			}

			if !strings.Contains(stderr.String(), testCase.wantStderr) {
				subtest.Errorf("run(%q) stderr = %q, want it to contain %q", testCase.arguments, &stderr, testCase.wantStderr)
			}

			if 0 != stdout.Len() {
				subtest.Errorf("run(%q) stdout = %q, want nothing", testCase.arguments, &stdout)
			}
		})
	}
}

// TestRunHelp checks that -h prints the usage and succeeds.
func TestRunHelp(test *testing.T) {
	test.Parallel()

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), []string{"-h"}, &stdout, &stderr); EXIT_SUCCESS != exitCode {
		test.Errorf("run(-h) = %d, want %d", exitCode, EXIT_SUCCESS)
	}

	if !strings.Contains(stderr.String(), "-sources") {
		test.Errorf("run(-h) stderr = %q, want the flag list", &stderr)
	}
}

// TestRunUnusableOutputDirectory checks that an output directory that can't be created is a
// runtime failure.
func TestRunUnusableOutputDirectory(test *testing.T) {
	test.Parallel()

	directory := test.TempDir()
	arguments := []string{
		"-sources", writeTestFile(test, directory, "sources.json", DISABLED_SOURCES),
		"-out", writeTestFile(test, directory, "file", ""),
		"-env", filepath.Join(directory, "missing.env"),
	}

	var stdout, stderr bytes.Buffer
	if exitCode := run(test.Context(), arguments, &stdout, &stderr); EXIT_FAILURE != exitCode {
		test.Errorf("run(%q) = %d, want %d", arguments, exitCode, EXIT_FAILURE)
	}

	if !strings.Contains(stderr.String(), "opening output directory failed") {
		test.Errorf("run(%q) stderr = %q, want the output directory failure", arguments, &stderr)
	}
}

// TestVersionFromBuildInfo checks the version reported for tagged, untagged and unknown builds.
func TestVersionFromBuildInfo(test *testing.T) {
	test.Parallel()

	revision := debug.BuildSetting{Key: VCS_REVISION_SETTING, Value: "0123abcd"}

	testCases := []struct {
		name      string
		buildInfo *debug.BuildInfo
		ok        bool
		want      string
	}{
		{name: "no build information", want: UNKNOWN_VERSION},
		{name: "tagged module", buildInfo: &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, ok: true, want: "v1.2.3"},
		{
			name:      "untagged build",
			buildInfo: &debug.BuildInfo{Main: debug.Module{Version: DEVELOPMENT_VERSION}, Settings: []debug.BuildSetting{revision}},
			ok:        true,
			want:      "0123abcd",
		},
		{name: "no version or revision", buildInfo: &debug.BuildInfo{}, ok: true, want: UNKNOWN_VERSION},
	}

	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			if got := versionFromBuildInfo(testCase.buildInfo, testCase.ok); testCase.want != got {
				subtest.Errorf("versionFromBuildInfo(%+v, %v) = %q, want %q", testCase.buildInfo, testCase.ok, got, testCase.want)
			}
		})
	}
}

// TestBuildVersion checks that the running binary reports some version.
func TestBuildVersion(test *testing.T) {
	test.Parallel()

	if "" == buildVersion() {
		test.Error(`buildVersion() = "", want a version or "unknown"`)
	}
}

// TestNewHTTPClient checks that the shared client has a timeout, so a slow upstream can't hang
// the run.
func TestNewHTTPClient(test *testing.T) {
	test.Parallel()

	if DEFAULT_HTTP_TIMEOUT != newHTTPClient().Timeout {
		test.Errorf("newHTTPClient().Timeout = %v, want %v", newHTTPClient().Timeout, DEFAULT_HTTP_TIMEOUT)
	}
}

// writeTestFile writes content to name inside directory and returns the file's path.
func writeTestFile(testingContext testing.TB, directory, name, content string) string {
	testingContext.Helper()

	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(content), 0o600); nil != err {
		testingContext.Fatalf("writing %q: %v", name, err)
	}

	return path
}
