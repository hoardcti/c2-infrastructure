// Command aggregator fetches the C2 feeds enabled in sources.json and stores every reported IP
// address as a JSON file under the output directory, merging new sightings into existing files.
//
// Usage:
//
//	aggregator [-sources FILE] [-out DIR] [-env FILE] [-log FORMAT] [-level LEVEL]
//
// Flags:
//
//	-sources  path to the sources file (default "sources.json")
//	-out      output directory (default "out")
//	-env      optional .env file to load (default ".env")
//	-log      log format, "text" or "json" (default "text")
//	-level    minimum log level: "debug", "info", "warn" or "error" (default "info")
//
// Environment:
//
//	ABUSECH_API_KEY  the abuse.ch Auth-Key; required while the threatfox source is enabled
//
// It prints the number of stored payloads to standard output and logs to standard error.
//
// Exit codes: 0 on success, 1 on a runtime failure such as an unreachable upstream, 2 on a
// usage error such as an unknown flag or an invalid sources file.
//
// Example:
//
//	aggregator -out out -log json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/hoardcti/c2-infrastructure/internal/aggregator"
)

// Exit codes returned by run.
const (
	// EXIT_SUCCESS means every enabled source was processed.
	EXIT_SUCCESS = 0
	// EXIT_FAILURE means a runtime failure, such as an unreachable upstream or a disk error.
	EXIT_FAILURE = 1
	// EXIT_USAGE means invalid flags, environment or sources file.
	EXIT_USAGE = 2
)

// Command-line defaults and settings.
const (
	// PROGRAM_NAME is the command's name in usage and error messages.
	PROGRAM_NAME = "aggregator"
	// DEFAULT_SOURCES_PATH is the sources configuration file, relative to the working
	// directory.
	DEFAULT_SOURCES_PATH = "sources.json"
	// DEFAULT_OUTPUT_DIRECTORY is where IP address files are written.
	DEFAULT_OUTPUT_DIRECTORY = "out"
	// DEFAULT_ENV_FILE is the optional .env file loaded before the environment is read.
	DEFAULT_ENV_FILE = ".env"
	// LOG_FORMAT_TEXT selects human-readable logs, for local runs.
	LOG_FORMAT_TEXT = "text"
	// LOG_FORMAT_JSON selects machine-readable logs, for CI.
	LOG_FORMAT_JSON = "json"
	// DEFAULT_LOG_FORMAT is the log format when -log isn't given.
	DEFAULT_LOG_FORMAT = LOG_FORMAT_TEXT
	// ABUSECH_API_KEY_VARIABLE is the environment variable holding the abuse.ch Auth-Key.
	ABUSECH_API_KEY_VARIABLE = "ABUSECH_API_KEY"
	// DEFAULT_HTTP_TIMEOUT bounds each upstream request, including reading the response.
	DEFAULT_HTTP_TIMEOUT = 2 * time.Minute
	// USER_AGENT_PRODUCT starts the User-Agent sent upstream; the program's version follows.
	USER_AGENT_PRODUCT = "hoardcti-c2-infrastructure/"
	// USER_AGENT_CONTACT ends the User-Agent with where the requests come from.
	USER_AGENT_CONTACT = " (+" + aggregator.PROJECT_URL + ")"
	// UNKNOWN_VERSION is reported when the binary carries no version information.
	UNKNOWN_VERSION = "unknown"
	// DEVELOPMENT_VERSION is the module version Go records for a build that isn't from a
	// tagged module.
	DEVELOPMENT_VERSION = "(devel)"
	// VCS_REVISION_SETTING is the build setting holding the Git commit a binary was built from.
	VCS_REVISION_SETTING = "vcs.revision"
)

// configuration holds every setting the command needs, resolved from flags, the environment
// and defaults.
type configuration struct {
	// sourcesPath is the sources configuration file.
	sourcesPath string
	// outputDirectory is where IP address files are written.
	outputDirectory string
	// logFormat is LOG_FORMAT_TEXT or LOG_FORMAT_JSON.
	logFormat string
	// logLevel is the minimum level logged.
	logLevel slog.Level
	// abusechAPIKey authenticates ThreatFox requests; empty when unset.
	abusechAPIKey aggregator.APIKey
}

// main runs the command and exits with its exit code. os.Exit skips deferred calls, so it's
// only called here, after run has finished and cleaned up.
func main() { // coverage-ignore -- only calls run, which is fully tested.
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command with the given arguments and returns its exit code.
func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	// Stop cleanly on Ctrl+C or SIGTERM: ctx is cancelled, and the run stops before the next
	// source or file instead of being killed halfway through a write.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Resolve and check every setting before starting any work.
	settings, err := loadConfiguration(arguments, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return EXIT_SUCCESS
	}

	if nil != err {
		fmt.Fprintf(stderr, "%s: %v\n", PROGRAM_NAME, err)

		return EXIT_USAGE
	}

	logger := newLogger(settings.logFormat, settings.logLevel, stderr)
	version := buildVersion()

	sources, err := aggregator.LoadSources(settings.sourcesPath)
	if nil != err {
		logger.ErrorContext(ctx, "loading sources failed", "error", err)

		return EXIT_USAGE
	}

	// Build the dependencies once and pass them down.
	store, err := aggregator.NewStore(settings.outputDirectory)
	if nil != err {
		logger.ErrorContext(ctx, "opening output directory failed", "error", err)

		return EXIT_FAILURE
	}
	// defer runs this function when run returns, on every return path, so the output
	// directory is always released.
	defer func() {
		if closeErr := store.Close(); nil != closeErr { // coverage-ignore -- see Store.Close.
			logger.WarnContext(ctx, "closing output directory failed", "error", closeErr)
		}
	}()

	sourceAggregator, err := aggregator.New(
		sources,
		store,
		newHTTPClient(),
		aggregator.WithLogger(logger),
		aggregator.WithUserAgent(USER_AGENT_PRODUCT+version+USER_AGENT_CONTACT),
		aggregator.WithAbusechAPIKey(settings.abusechAPIKey),
	)
	if nil != err {
		logger.ErrorContext(ctx, "checking sources failed", "error", err)

		return EXIT_USAGE
	}

	// Do the work and report the outcome once. The count is printed even after a failure,
	// because the sources that succeeded were still stored.
	logger.InfoContext(ctx, "aggregation started", "version", version)
	storedCount, err := sourceAggregator.Run(ctx)
	fmt.Fprintf(stdout, "stored %d payloads\n", storedCount)

	if nil != err {
		logger.ErrorContext(ctx, "aggregation failed", "error", err)

		return EXIT_FAILURE
	}

	logger.InfoContext(ctx, "aggregation finished")

	return EXIT_SUCCESS
}

// loadConfiguration parses the command-line flags, loads the .env file and reads the
// environment. Flag problems are reported on stderr by the flag package as well as in the
// returned error. It returns an error wrapping flag.ErrHelp when -h or -help was given.
func loadConfiguration(arguments []string, stderr io.Writer) (configuration, error) {
	// A flag set of our own, rather than the flag package's global one, lets tests call run
	// with any arguments; ContinueOnError returns errors instead of exiting.
	flags := flag.NewFlagSet(PROGRAM_NAME, flag.ContinueOnError)
	flags.SetOutput(stderr)

	sourcesPath := flags.String("sources", DEFAULT_SOURCES_PATH, "path to the sources file")
	outputDirectory := flags.String("out", DEFAULT_OUTPUT_DIRECTORY, "output directory")
	environmentFile := flags.String("env", DEFAULT_ENV_FILE, "optional .env file to load")
	logFormat := flags.String("log", DEFAULT_LOG_FORMAT, `log format, "text" or "json"`)

	// A zero-value slog.Level is Info, which TextVar also sets as the default.
	var logLevel slog.Level
	flags.TextVar(&logLevel, "level", slog.LevelInfo, `minimum log level, such as "debug"`)

	if err := flags.Parse(arguments); nil != err {
		return configuration{}, fmt.Errorf("parsing flags: %w", err)
	}

	// Check every value before anything is loaded.
	if 0 != flags.NArg() {
		return configuration{}, fmt.Errorf("unexpected arguments %q", flags.Args())
	}

	isKnownLogFormat := LOG_FORMAT_TEXT == *logFormat || LOG_FORMAT_JSON == *logFormat
	if !isKnownLogFormat {
		return configuration{}, fmt.Errorf("unknown log format %q", *logFormat)
	}

	// The .env file is optional, and it never overrides variables already set in the
	// environment, so CI's real secrets always win over a developer's file.
	if err := godotenv.Load(*environmentFile); nil != err && !errors.Is(err, fs.ErrNotExist) {
		return configuration{}, fmt.Errorf("loading %q: %w", *environmentFile, err)
	}

	return configuration{
		sourcesPath:     *sourcesPath,
		outputDirectory: *outputDirectory,
		logFormat:       *logFormat,
		logLevel:        logLevel,
		abusechAPIKey:   aggregator.APIKey(os.Getenv(ABUSECH_API_KEY_VARIABLE)),
	}, nil
}

// newLogger builds the program's logger, writing to stderr in the given format, which is
// LOG_FORMAT_TEXT or LOG_FORMAT_JSON.
func newLogger(format string, level slog.Level, stderr io.Writer) *slog.Logger {
	options := &slog.HandlerOptions{Level: level}
	if LOG_FORMAT_JSON == format {
		return slog.New(slog.NewJSONHandler(stderr, options))
	}

	return slog.New(slog.NewTextHandler(stderr, options))
}

// buildVersion returns the version of the running binary (see versionFromBuildInfo).
func buildVersion() string {
	// Go functions can return several values: ok is false when the binary has no build
	// information.
	buildInfo, ok := debug.ReadBuildInfo()

	return versionFromBuildInfo(buildInfo, ok)
}

// versionFromBuildInfo returns the module version recorded in buildInfo, or the Git commit
// for a build that isn't from a tagged module, or UNKNOWN_VERSION.
func versionFromBuildInfo(buildInfo *debug.BuildInfo, ok bool) string {
	if !ok {
		return UNKNOWN_VERSION
	}

	isTaggedBuild := "" != buildInfo.Main.Version && DEVELOPMENT_VERSION != buildInfo.Main.Version
	if isTaggedBuild {
		return buildInfo.Main.Version
	}

	for _, setting := range buildInfo.Settings {
		if VCS_REVISION_SETTING == setting.Key {
			return setting.Value
		}
	}

	return UNKNOWN_VERSION
}

// newHTTPClient builds the client shared by every upstream request in a run. Its timeout
// covers the whole exchange, including reading the body.
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: DEFAULT_HTTP_TIMEOUT}
}
