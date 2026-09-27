//go:build ruleguard

// Package gorules holds hoardCTI's custom lint rules for gocritic's ruleguard
// checker. They enforce the Yoda-condition house rule (GO-CTL-001 to
// GO-CTL-003), which no off-the-shelf linter supports.
//
// The build constraint above keeps this file out of normal builds: only
// golangci-lint reads it, through the gocritic ruleguard setting in
// .golangci.yml. The module needs github.com/quasilyte/go-ruleguard/dsl as a
// dependency so that `go mod tidy` keeps it.
//
// The Where conditions are written in ruleguard's DSL, which only accepts the
// matched value on the left (matcher["value"].Text != "nil"), so this file
// can't follow the Yoda rule it enforces. Because of its build constraint it's
// never linted itself.
//
// STATUS: starting point, not yet run against a real repository. Check every
// rule against the examples in language/control-flow.md when adopting it.
package gorules

import "github.com/quasilyte/go-ruleguard/dsl"

// yodaNil reports comparisons with nil on the right (GO-CTL-001, GO-CTL-002).
func yodaNil(matcher dsl.Matcher) {
	matcher.Match(`$value == nil`).
		Where(!matcher["value"].Const && matcher["value"].Text != "nil").
		Report(`put nil on the left: nil == $value (GO-CTL-001)`).
		Suggest(`nil == $value`)

	matcher.Match(`$value != nil`).
		Where(!matcher["value"].Const && matcher["value"].Text != "nil").
		Report(`put nil on the left: nil != $value (GO-CTL-001)`).
		Suggest(`nil != $value`)
}

// yodaConstant reports comparisons with a literal, named constant or enum value
// on the right (GO-CTL-001, GO-CTL-002). Booleans are handled by booleanLiteral.
func yodaConstant(matcher dsl.Matcher) {
	matcher.Match(`$value == $constant`).
		Where(matcher["constant"].Const &&
			!matcher["value"].Const &&
			matcher["constant"].Text != "true" &&
			matcher["constant"].Text != "false").
		Report(`put the constant on the left: $constant == $value (GO-CTL-001)`).
		Suggest(`$constant == $value`)

	matcher.Match(`$value != $constant`).
		Where(matcher["constant"].Const &&
			!matcher["value"].Const &&
			matcher["constant"].Text != "true" &&
			matcher["constant"].Text != "false").
		Report(`put the constant on the left: $constant != $value (GO-CTL-001)`).
		Suggest(`$constant != $value`)
}

// yodaSentinel reports comparisons with a sentinel error variable on the right
// (GO-CTL-002). Prefer errors.Is (GO-ERR-009); this catches direct comparisons
// that remain, such as io.EOF from a reader.
func yodaSentinel(matcher dsl.Matcher) {
	matcher.Match(`$value == $sentinel`, `$value != $sentinel`).
		Where(matcher["sentinel"].Text.Matches(`^([a-z0-9]+\.)?[Ee]rr[A-Z0-9]\w*$|^io\.EOF$`) &&
			!matcher["value"].Text.Matches(`^([a-z0-9]+\.)?[Ee]rr[A-Z0-9]\w*$|^io\.EOF$`)).
		Report(`put the sentinel error on the left (GO-CTL-002), or use errors.Is (GO-ERR-009)`)
}

// booleanLiteral reports comparisons with true or false (GO-CTL-003).
func booleanLiteral(matcher dsl.Matcher) {
	matcher.Match(`$value == true`, `true == $value`, `$value != false`, `false != $value`).
		Report(`test the boolean directly: $value (GO-CTL-003)`).
		Suggest(`$value`)

	matcher.Match(`$value == false`, `false == $value`, `$value != true`, `true != $value`).
		Report(`test the boolean directly: !$value (GO-CTL-003)`).
		Suggest(`!$value`)
}
