# Contributing

Thanks for helping improve hoardCTI. This document covers how we work across
every repository in the organisation.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security first

**Never open a public issue or pull request for a vulnerability.** Follow
[SECURITY.md](SECURITY.md), which routes reports privately.

hoardCTI is consumed by organisations that rely on it for their own defence.
Treat correctness and integrity of intelligence data as a security property,
not just a quality one.

## Getting started

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests.
3. Open a pull request using the template.

Branch naming: `<type>/<short-description>` — for example `fix/feed-parser-timeout`
or `feat/stix-2.1-export`. Types: `feat`, `fix`, `docs`, `refactor`, `test`,
`chore`, `ci`, `perf`, `build`, `revert`.

## Pull request titles

Repositories squash-merge using the **pull request title** as the commit
message, so the title must follow Conventional Commits — CI checks it. The
subject should start lower-case and not end with a full stop:

```
feat(parser): support STIX 2.1 bundles
fix: handle empty response from upstream feed
```

Retitling a pull request re-runs the check on its own.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<optional scope>): <description>

<optional body explaining why, not what>

<optional footer: Closes #123, BREAKING CHANGE: ...>
```

Write the body to explain *why* the change is needed. The diff already shows
what changed; it cannot show what you were thinking.

## Pull requests

**Keep them small.** The PR Size Check warns above 1000 additions, 1000
deletions, or 1500 total changed lines, excluding generated and vendored files.
The warning does not block merge, but a large PR usually means several
independent changes that should be reviewed separately. Reviewers may ask you
to split it.

Every pull request needs:

- A passing CI run
- Approval from a [code owner](.github/CODEOWNERS)
- A clean secret scan
- Tests covering new or changed behaviour

Rebase or update your branch rather than merging `main` into it repeatedly, so
the history stays readable.

## Testing

Run the checks locally before pushing. For this template repository:

```bash
python -m unittest discover -s .github/scripts -p "test_*.py" -v
```

Lint and format Python (rules are configured in `pyproject.toml`):

```bash
ruff check . && ruff format --check .
```

Audit the workflows for security problems:

```bash
zizmor --config .github/zizmor.yml .github/workflows/
```

Scan your working tree for credentials before you commit:

```bash
python .github/scripts/secret_scan.py --mode tree
```

Projects generated from this template add their own test commands here. New
repositories are expected to have a real test suite wired into
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) — the CI file ships with
workflow linting and scanner tests already, and you extend it.

## Never commit credentials

The secret scanner runs on every pull request and on a schedule across the
whole tree, but it is a safety net, not a guarantee. Use environment variables
or a secret manager; keep real values out of the repository entirely.

If the scanner produces a false positive, add an explicit, greppable
suppression to that line:

```python
token = "not-actually-a-secret"  # pragma: allowlist secret
```

Do not broaden the scanner's allowlist patterns to silence a single case —
line-content allowlists are how real credentials get missed.

**If you have committed a real credential:** stop, tell the maintainers
privately, and rotate it. Rotation is mandatory. Deleting the file does not
help — the value remains in the git history and must be assumed compromised.

## GitHub Actions

Any new action must be pinned to a **full 40-character commit SHA**, with the
version in a trailing comment so Dependabot can track it:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

Version tags are mutable and can be repointed by anyone who compromises the
upstream repository. Given what hoardCTI publishes, that is a threat model we
should not be exposed to.

Workflows must declare least-privilege `permissions`, set `timeout-minutes`, and
use a `concurrency` group. `pull_request_target` workflows must never check out
or execute pull request code.

## Style

[`.editorconfig`](.editorconfig) sets the baseline (UTF-8, LF, trimmed trailing
whitespace, final newline). Most editors apply it automatically; some need a
plugin. Match the surrounding code's conventions, and add a project-specific
formatter and linter to CI where the language has an obvious one.

## Licence

Contributions are accepted under the repository's [licence](LICENSE). Ensure you
have the right to contribute the code you submit.
