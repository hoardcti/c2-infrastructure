// Command aggregator collects C2 intelligence from the sources enabled in sources.json and
// keeps one JSON record per IP address under the output directory. Each record holds every
// observation every source has reported about the address, so its whole history is kept.
//
// Feeds (such as ThreatFox) run first and add C2 servers; enrichers (such as Shodan or
// VirusTotal) then look up addresses in the dataset within their configured budgets.
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
// Environment (each is required only while a source that uses it is enabled):
//
//	ABUSECH_API_KEY     abuse.ch Auth-Key, for threatfox and urlhaus
//	IPINFO_TOKEN        IPinfo token, for ipinfo
//	VIRUSTOTAL_API_KEY  VirusTotal key, for virustotal
//	ABUSEIPDB_API_KEY   AbuseIPDB key, for abuseipdb
//	OTX_API_KEY         AlienVault OTX key, for otx
//	SHODAN_API_KEY      Shodan key, for shodan
//
// It prints the number of record files written to standard output and logs to standard error.
//
// Exit codes: 0 on success, 1 on a runtime failure such as an unreachable upstream, 2 on a
// usage error such as an unknown flag, an invalid sources file or a missing key.
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
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/abuseipdb"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/criminalip"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/feodotracker"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/internetdb"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/ipinfo"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/otx"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/shodan"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/spamhaus"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/threatfox"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/urlhaus"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/viribacktracker"
	"github.com/hoardcti/c2-infrastructure/internal/aggregator/virustotal"
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

// Environment variables holding the sources' credentials.
const (
	// ABUSECH_API_KEY_VARIABLE holds the abuse.ch Auth-Key, used by ThreatFox and URLhaus.
	ABUSECH_API_KEY_VARIABLE = "ABUSECH_API_KEY"
	// IPINFO_TOKEN_VARIABLE holds the IPinfo token.
	IPINFO_TOKEN_VARIABLE = "IPINFO_TOKEN"
	// VIRUSTOTAL_API_KEY_VARIABLE holds the VirusTotal key.
	VIRUSTOTAL_API_KEY_VARIABLE = "VIRUSTOTAL_API_KEY"
	// ABUSEIPDB_API_KEY_VARIABLE holds the AbuseIPDB key.
	ABUSEIPDB_API_KEY_VARIABLE = "ABUSEIPDB_API_KEY"
	// OTX_API_KEY_VARIABLE holds the AlienVault OTX key.
	OTX_API_KEY_VARIABLE = "OTX_API_KEY"
	// SHODAN_API_KEY_VARIABLE holds the Shodan key.
	SHODAN_API_KEY_VARIABLE = "SHODAN_API_KEY"
)

// errUnknownSource is returned for an enabled source whose name no package handles.
var errUnknownSource = errors.New("no source has this name")

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
	// apiKeys maps each credential's environment variable to its value; a variable that is
	// unset or empty is missing.
	apiKeys map[string]aggregator.APIKey
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

	sources, err := aggregator.LoadConfiguration(settings.sourcesPath)
	if nil != err {
		logger.ErrorContext(ctx, "loading sources failed", "error", err)

		return EXIT_USAGE
	}

	// Build the dependencies once and pass them down. Every source shares one HTTP client.
	sourceOptions, err := newSourceOptions(sources, sourceDependencies{
		apiKeys:    settings.apiKeys,
		httpClient: newHTTPClient(),
		userAgent:  USER_AGENT_PRODUCT + version + USER_AGENT_CONTACT,
		logger:     logger,
	})
	if nil != err {
		logger.ErrorContext(ctx, "checking sources failed", "error", err)

		return EXIT_USAGE
	}

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

	sourceAggregator, err := aggregator.New(store, append(sourceOptions, aggregator.WithLogger(logger))...)
	if nil != err {
		logger.ErrorContext(ctx, "checking sources failed", "error", err)

		return EXIT_USAGE
	}

	// Do the work and report the outcome once. The count is printed even after a failure,
	// because the sources that succeeded were still stored.
	logger.InfoContext(ctx, "aggregation started", "version", version)
	writtenCount, err := sourceAggregator.Run(ctx)
	fmt.Fprintf(stdout, "wrote %d records\n", writtenCount)

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
		apiKeys:         readAPIKeys(),
	}, nil
}

// readAPIKeys reads every credential variable from the environment.
func readAPIKeys() map[string]aggregator.APIKey {
	apiKeys := map[string]aggregator.APIKey{}

	for _, variable := range []string{
		ABUSECH_API_KEY_VARIABLE,
		IPINFO_TOKEN_VARIABLE,
		VIRUSTOTAL_API_KEY_VARIABLE,
		ABUSEIPDB_API_KEY_VARIABLE,
		OTX_API_KEY_VARIABLE,
		SHODAN_API_KEY_VARIABLE,
	} {
		apiKeys[variable] = aggregator.APIKey(os.Getenv(variable))
	}

	return apiKeys
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

// sourceDependencies is what every source is built with.
type sourceDependencies struct {
	// apiKeys maps each credential's environment variable to its value.
	apiKeys map[string]aggregator.APIKey
	// httpClient is shared by every source.
	httpClient *http.Client
	// userAgent is sent with every request.
	userAgent string
	// logger receives the sources' warnings.
	logger *slog.Logger
}

// newSourceOptions builds an aggregator option for every enabled source in sources, feeds first.
// Every problem is reported at once, before any work starts.
func newSourceOptions(sources aggregator.Configuration, dependencies sourceDependencies) ([]aggregator.Option, error) {
	var (
		options  []aggregator.Option
		problems []error
	)

	// The function literal is a closure: it appends to options and problems from here.
	add := func(config aggregator.SourceConfig, newOption func(aggregator.SourceConfig, sourceDependencies) (aggregator.Option, error)) {
		if !config.Enabled {
			return
		}

		option, err := newOption(config, dependencies)
		if nil != err {
			problems = append(problems, fmt.Errorf("source %q: %w", config.Name, err))

			return
		}

		options = append(options, option)
	}

	for _, config := range sources.Feeds {
		add(config, newFeedOption)
	}

	for _, config := range sources.Enrichers {
		add(config, newEnricherOption)
	}

	return options, errors.Join(problems...)
}

// newFeedOption builds the feed named in config.
func newFeedOption(config aggregator.SourceConfig, dependencies sourceDependencies) (aggregator.Option, error) {
	apiKey, upstream, err := dependencies.prepare(config)
	if nil != err {
		return nil, err
	}

	logger := dependencies.logger

	// The function literal is a closure: it uses config from here. A failed constructor
	// returns a nil pointer, which it never stores because err is set.
	feedOption := func(feed aggregator.Feed, err error) (aggregator.Option, error) {
		if nil != err {
			return nil, err
		}

		return aggregator.WithFeed(config.Name, feed), nil
	}

	switch config.Name {
	case threatfox.SOURCE_NAME:
		return feedOption(threatfox.New(config, upstream, apiKey, logger))
	case feodotracker.SOURCE_NAME:
		return feedOption(feodotracker.New(config, upstream, logger))
	case viribacktracker.SOURCE_NAME:
		return feedOption(viribacktracker.New(config, upstream, logger))
	case criminalip.SOURCE_NAME:
		return feedOption(criminalip.New(config, upstream, logger))
	}

	return nil, errUnknownSource
}

// newEnricherOption builds the enricher named in config, with its schedule.
func newEnricherOption(config aggregator.SourceConfig, dependencies sourceDependencies) (aggregator.Option, error) {
	schedule, err := config.Schedule()
	if nil != err {
		return nil, fmt.Errorf("checking schedule: %w", err)
	}

	apiKey, upstream, err := dependencies.prepare(config)
	if nil != err {
		return nil, err
	}

	// The function literal is a closure: it uses config and schedule from here. A failed
	// constructor returns a nil pointer, which it never stores because err is set.
	enricherOption := func(enricher aggregator.Enricher, err error) (aggregator.Option, error) {
		if nil != err {
			return nil, err
		}

		return aggregator.WithEnricher(config.Name, enricher, schedule), nil
	}

	switch config.Name {
	case urlhaus.SOURCE_NAME:
		return enricherOption(urlhaus.New(config, upstream, apiKey))
	case spamhaus.SOURCE_NAME:
		return enricherOption(spamhaus.New(config, upstream))
	case internetdb.SOURCE_NAME:
		return enricherOption(internetdb.New(config, upstream))
	case ipinfo.SOURCE_NAME:
		return enricherOption(ipinfo.New(config, upstream, apiKey))
	case virustotal.SOURCE_NAME:
		return enricherOption(virustotal.New(config, upstream, apiKey))
	case abuseipdb.SOURCE_NAME:
		return enricherOption(abuseipdb.New(config, upstream, apiKey))
	case otx.SOURCE_NAME:
		return enricherOption(otx.New(config, upstream, apiKey))
	case shodan.SOURCE_NAME:
		return enricherOption(shodan.New(config, upstream, apiKey))
	}

	return nil, errUnknownSource
}

// prepare returns the credential the source named in config needs, if any, and an Upstream
// that sends its requests at its configured rate and keeps the credential out of errors. It
// fails if the source needs a credential that isn't set.
func (dependencies sourceDependencies) prepare(
	config aggregator.SourceConfig,
) (aggregator.APIKey, *aggregator.Upstream, error) {
	// A source missing from the map needs no credential: the comma-ok form reports whether the
	// name is in the map.
	variable, needsKey := credentialVariables()[config.Name]

	apiKey := dependencies.apiKeys[variable]
	if needsKey && "" == apiKey {
		return "", nil, fmt.Errorf("the %s environment variable is required", variable)
	}

	upstream, err := aggregator.NewUpstream(
		dependencies.httpClient,
		config.RequestsPerMinute,
		aggregator.WithUserAgent(dependencies.userAgent),
		aggregator.WithRedactedSecret(apiKey),
	)
	if nil != err {
		return "", nil, fmt.Errorf("checking requests_per_minute: %w", err)
	}

	return apiKey, upstream, nil
}

// credentialVariables maps each source that needs a credential to the environment variable
// that holds it.
func credentialVariables() map[string]string {
	return map[string]string{
		threatfox.SOURCE_NAME:  ABUSECH_API_KEY_VARIABLE,
		urlhaus.SOURCE_NAME:    ABUSECH_API_KEY_VARIABLE,
		ipinfo.SOURCE_NAME:     IPINFO_TOKEN_VARIABLE,
		virustotal.SOURCE_NAME: VIRUSTOTAL_API_KEY_VARIABLE,
		abuseipdb.SOURCE_NAME:  ABUSEIPDB_API_KEY_VARIABLE,
		otx.SOURCE_NAME:        OTX_API_KEY_VARIABLE,
		shodan.SOURCE_NAME:     SHODAN_API_KEY_VARIABLE,
	}
}
