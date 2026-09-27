# Instructions for AI coding assistants

This repository follows the **hoardCTI Go style guide**:
https://github.com/hoardcti/golang-style-guide. Read it before writing code. Its
house rules differ from common Go style **on purpose**, so don't "fix" code
back to the usual conventions.

## House rules that differ from typical Go

1. **Yoda comparisons** for `==` and `!=`: `nil != err`, `"" == name`,
   `http.StatusOK != response.StatusCode`, `0 == len(items)`. With two
   variables, the expected value goes on the left: `want != got`. Booleans are
   tested directly (`!ok`), never compared with `true` or `false`. Relational
   operators (`<`, `>=`) keep their natural order.
2. **Constants are SCREAMING_SNAKE_CASE**: `MAX_RETRIES`, `DEFAULT_HTTP_TIMEOUT`.
3. **Descriptive names**. The only allowed short names are `err`, `ctx`, `ok`,
   `i`, `j`, `k`, `v`, `w`, `r`, `id`, `db`, `tx`, `fn` and `n`.
   Receivers are words (`client *Client`, not `c *Client`). Tests use
   `test *testing.T`, subtests `subtest *testing.T`, benchmarks
   `benchmark *testing.B`, and fuzz targets `fuzzer *testing.F`. Tables are
   `testCases`/`testCase`. Use `waitGroup` and `mutex`, never `wg`/`mu`.
4. **Comment everything**: every declaration (exported or not), every test,
   and a comment before each logical block in functions longer than about 10
   lines. Explain Go mechanisms (`defer`, goroutines, channels, `select`,
   struct tags, and so on) once per file for readers who don't know Go.
   British English, full sentences, full stops.
5. **Minimal and modular**: a helper with one caller stays in the caller's
   file, directly below it. Don't create new files or packages for code with a
   single user. Never create `types.go`.
6. **100% test coverage** per package and in total. Test commands through
   `run(ctx, arguments, stdout, stderr) int`. Use `// coverage-ignore -- reason`
   only for truly unreachable code.

## Other rules that are easy to miss

- Go 1.27 idioms: `for range n`, `waitGroup.Go`, `errors.AsType`, `new(value)`,
  `encoding/json/v2`, `omitzero`, standard `uuid`, `test.Context()`,
  `benchmark.Loop()`, `testing/synctest` (never `time.Sleep` in tests).
- `log/slog` only, with the logger passed in. Lower-case constant messages and
  snake_case keys.
- Errors: lower-case gerund phrases (`"fetching export: %w"`), no package
  prefix, wrapped with `%w`, handled once (log it or return it, never both),
  and never containing secrets.
- No `init()`, no changeable globals, no `unsafe`/`reflect`/cgo, no `goto`, no
  `fallthrough`, no naked returns, no dot imports.
- Import groups: standard library / third party / `github.com/hoardcti`.
- Files are `snake_case.go`. Everything except `main` packages lives under
  `internal/`.

## Before you finish

Run `make check` and fix everything it reports. It runs exactly what CI runs.

## This repository

- Published JSON keeps its existing field names (`firstSeen`, `scanTime`,
  `lastOnline`) and its timestamp format (ISO 8601 without a zone, in UTC) so
  consumers see one format across old and new files. Those struct tags carry
  `//nolint:tagliatelle` on purpose; changing the output format is a separate,
  deliberate decision, not a style fix.
- Each source in `sources.json` has an explicit `enabled` flag.
- Test fixtures and their origins are listed in
  `internal/aggregator/testdata/README.md`.
- `go.mod` pins `toolchain go1.27.1`. If your installed Go is older, leave
  `GOTOOLCHAIN` at `auto` so the `go` command downloads it.
