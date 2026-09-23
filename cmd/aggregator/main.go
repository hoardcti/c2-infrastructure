// Command aggregator fetches the C2 feeds listed in sources.json and stores
// every reported IP under the output directory.
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"

	"github.com/doodad-labs/command-server-watch/internal/aggregator"
	"github.com/doodad-labs/command-server-watch/internal/dotenv"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	os.Exit(run(ctx, os.Args[1:], os.Stderr))
}

// run parses args, loads the sources config and processes each configured
// feed. It returns the process exit code.
func run(ctx context.Context, args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("aggregator", flag.ContinueOnError)
	flags.SetOutput(stderr)

	sourcesFile := flags.String("sources", aggregator.DefaultSourcesFile, "path to the sources config")
	outputDir := flags.String("out", aggregator.DefaultOutputDir, "directory payloads are written to")
	envFile := flags.String("env", ".env", "path to the .env file")

	if err := flags.Parse(args); nil != err {
		return 2
	}

	logger := log.New(stderr, "", log.LstdFlags)

	if err := dotenv.Load(*envFile); nil != err {
		logger.Printf("Failed to load %s: %v", *envFile, err)
		return 1
	}

	sources, err := aggregator.LoadSources(*sourcesFile)
	if nil != err {
		logger.Printf("Failed to load sources: %v", err)
		return 1
	}

	a := aggregator.New(*outputDir)
	a.Logger = logger
	a.Run(ctx, sources)

	return 0
}
