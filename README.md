# c2-infrastructure

Collects command and control (C2) server IPs from public threat intelligence sources, enriches them with context from other CTI services, and keeps the complete, attributed history of every IP as a Hoard CTI record.

![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhoardcti%2Fc2-infrastructure%2Frefs%2Fheads%2Fmain%2Fstats.json&query=servers&label=C2%20Servers&color=A1BC98&style=flat-square) ![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhoardcti%2Fc2-infrastructure%2Frefs%2Fheads%2Fmain%2Fstats.json&query=last_edit&label=Last%20Updated&color=A1BC98&style=flat-square)

## Overview

Security tooling often needs to answer one question quickly: *is this IP a known C2 server, and what is it running?* Public trackers publish this data in different formats, field names and timestamp conventions, and enrichment services each describe an IP differently, so every consumer ends up writing the same integrations.

[`c2-infrastructure`](https://github.com/hoardcti/c2-infrastructure) is a Hoard CTI source module. Every hour it pulls C2 indicators from upstream trackers, looks the IPs up in enrichment services within their free quotas, and stores each IP as one JSON file holding everything every source has ever reported about it.

It records what public feeds and services report. It does not scan, probe or connect to the listed servers.

It is intended for:

- **Hoard CTI operators** running the aggregation platform
- **Defenders and tool authors** who want a normalised, pull-based C2 IP feed without writing per-source integrations

### Sources

There are two kinds of source. **Feeds** list C2 servers and add IPs to the dataset. **Enrichers** look up IPs already in the dataset and describe them; they never add IPs.

| Source | Kind | Status | Data | Key |
|---|---|---|---|---|
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | Feed | Active | `ip:port` IOCs tagged `c2`: malware family, port, threat type, confidence, first seen, Malpedia link, reference, tags | `ABUSECH_API_KEY` |
| [Feodo Tracker (abuse.ch)](https://feodotracker.abuse.ch/) | Feed | Disabled | Botnet C2 blocklist: malware family, port, status, AS, country, hostname, first seen, last online | None |
| [ViriBack C2 Tracker](https://tracker.viriback.com/) | Feed | Disabled | C2 panels from the last 30 days: family, panel URL, first seen | None |
| [Criminal IP C2 Daily Feed](https://github.com/criminalip/C2-Daily-Feed) | Feed | Disabled | Daily C2 list: family, port, score, country, scan time | None |
| [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) | Enricher | Active | Whether the IP lies in a hijacked or criminal netblock, with its SBL record | None |
| [IPinfo Lite](https://ipinfo.io/lite) | Enricher | Active | ASN, AS name and domain, country, continent | `IPINFO_TOKEN` |
| [Shodan InternetDB](https://internetdb.shodan.io/) | Enricher | Active | Open ports, hostnames, CPEs, Shodan tags, CVEs | None |
| [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/) | Enricher | Active | Malware download URLs hosted on the IP | `ABUSECH_API_KEY` |
| [AbuseIPDB](https://www.abuseipdb.com/) | Enricher | Active | Abuse confidence score, report counts, usage type, ISP | `ABUSEIPDB_API_KEY` |
| [AlienVault OTX](https://otx.alienvault.com/) | Enricher | Active | Pulses mentioning the IP, with malware families, tags and TLP | `OTX_API_KEY` |
| [Shodan](https://www.shodan.io/) | Enricher | Active | Services with product, version, HTTP title, TLS certificate and JARM | `SHODAN_API_KEY` |
| [VirusTotal](https://www.virustotal.com/) | Enricher | Active | Vendor verdicts, reputation, network, JARM, partner notes | `VIRUSTOTAL_API_KEY` |

Every source is listed in [`sources.json`](sources.json) with an explicit `enabled` flag; disabled sources are implemented and tested but switched off. Why these sources were chosen, and why others weren't, is in [`research.md`](research.md). How to get each key, and each service's limits and pricing, is in [`KEY.md`](KEY.md).

### Output

Each IP is written to its own JSON file in a directory tree that mirrors the address. IPv6 addresses use their fully expanded form:

```
ipv4/1/15/76/39.json
ipv6/2001/0db8/85a3/0000/0000/8a2e/0370/7334.json
```

The file holds the IP's complete history. Each source's reports are kept separately under its own name, so every piece of intelligence can be traced to where it came from:

```json
{
    "schema_version": 2,
    "ip": "1.15.76.39",
    "first_seen": "2026-09-14T11:57:26.201665Z",
    "last_seen": "2026-10-01T12:17:01Z",
    "flags": ["cobalt strike"],
    "sources": {
        "threatfox": {
            "last_checked": "2026-10-01T12:17:01Z",
            "observations": [
                {
                    "key": "1917335",
                    "first_observed": "2026-10-01T12:13:08Z",
                    "last_observed": "2026-10-01T12:17:01Z",
                    "flags": ["cobalt strike"],
                    "data": {
                        "ioc": "1.15.76.39:50050",
                        "port": 50050,
                        "threat_type": "botnet_cc",
                        "malware": "Cobalt Strike",
                        "confidence_level": 50,
                        "first_seen": "2026-09-14T11:11:41Z",
                        "...": "..."
                    }
                }
            ]
        },
        "shodan": {
            "last_checked": "2026-10-01T11:52:15Z",
            "observations": [
                {
                    "first_observed": "2026-10-01T11:52:15Z",
                    "last_observed": "2026-10-01T11:52:15Z",
                    "data": { "tags": ["c2", "self-signed"], "services": ["..."] }
                }
            ]
        }
    }
}
```

| Field | Meaning |
|---|---|
| `schema_version` | `2`. Files without it are the earlier format (see [Migration](#migration-from-version-1)). |
| `ip` | The address. |
| `first_seen`, `last_seen` | The first and last time any source reported the IP as a C2 server: the earliest `first_observed` and latest `last_observed` of observations with flags. Enrichment alone doesn't change them. |
| `flags` | Sorted union of every observation's flags: the lower-cased malware families feeds have reported. |
| `sources.<name>` | Everything the source named in `sources.json` has reported about the IP. |
| `sources.<name>.last_checked` | When the source last answered for the IP, whether or not it had anything to report. A source that knows nothing about the IP has this and no observations. |
| `sources.<name>.last_error` | The most recent failed lookup (`occurred_at`, `message`), cleared once a lookup succeeds. |
| `sources.<name>.observations` | Every distinct report, oldest first. Never removed or changed, apart from `last_observed`. |
| `observations[].key` | What the observation is about within the source, such as a ThreatFox IOC ID, a port or a panel URL. Absent for sources that report one thing per IP. |
| `observations[].first_observed`, `last_observed` | When this module first and last collected exactly this report. |
| `observations[].data` | The source's details. Each source package documents its fields in its `Data` type. |

Timestamps are RFC 3339 in UTC. Records are written atomically, with sorted keys, so a file only changes when its content does.

### How history is kept

Every run, each source's reports are merged into the IP's file without overwriting anything:

1. A report identical to the latest observation with the same `key` (same flags, and the same data in any key order) only moves that observation's `last_observed` forward. Repeated sightings therefore don't create duplicates.
2. Any other report is appended as a new observation. If Shodan reported `nginx` on port 443 last week and reports `Apache` today, both observations stay, each with the period it was seen.
3. Fields that change on every lookup without meaning anything, such as scan timestamps, raw banners and analysis dates, aren't stored, so they never create false changes. Lists whose upstream order means nothing are sorted.

### Migration from version 1

Files written before this format (`{ip, flags, results}`) are read and converted on the first run: every old result becomes an observation with its original metadata kept exactly as it was, and no `key`. Nothing is lost. The next report from the same source starts a new, keyed observation beside it, because version 1 didn't record what each result was about.

## Installation

This module is designed to run on GitHub Actions workers, so there is nothing to install to consume its data. The workflow in [`.github/workflows/`](.github/workflows/) builds and runs it every hour, commits the records to the `data` branch and updates [`stats.json`](stats.json) on `main`.

To run it on a fork, add these repository secrets. [`KEY.md`](KEY.md) explains how to get each one:

| Secret | Purpose |
|---|---|
| `ABUSECH_API_KEY` | abuse.ch Auth-Key, for ThreatFox and URLhaus |
| `IPINFO_TOKEN` | IPinfo token, for IPinfo Lite |
| `VIRUSTOTAL_API_KEY` | VirusTotal key |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key |
| `OTX_API_KEY` | AlienVault OTX key |
| `SHODAN_API_KEY` | Shodan key |
| `BOT_PAT` | Token with write access, used to push to the `data` and `main` branches |

A source whose key is missing stops the run with a configuration error, so either add its secret or disable it in `sources.json`.

For local development, build from source. `go.mod` pins Go 1.27.1; with an older Go installed, leave `GOTOOLCHAIN` at its default (`auto`) and the `go` command downloads the pinned version:

```bash
git clone https://github.com/hoardcti/c2-infrastructure.git
cd c2-infrastructure
make build
```

## Usage

### API

The API is the recommended way to query single IPs. It returns proper JSON on both hits and misses, and it is stable across the storage changes described below.

Look up an IP:

```bash
curl -fsSL https://api.hoardcti.com/v1/c2-infrastructure/<ip>
```

A `404` with `{"query_status":"not_found"}` means the IP is not in the dataset. A `400` with `{"query_status":"invalid_ip"}` means the input is not a valid IPv4 or IPv6 address.

Module metadata — version, server count, last update time and repository URL:

```bash
curl -fsSL https://api.hoardcti.com/v1/c2-infrastructure/
```

Lookups accept IPv4 and IPv6 addresses, in any IPv6 notation. Responses are cached for 5 minutes.

### Direct access

> [!WARNING]
> Storing output on the `data` branch is **temporary**. The storage and distribution mechanism will change as Hoard CTI's architecture is finalised. Do not build production integrations against the `data` branch or its layout — use the API above.

All collected data is currently committed to the [`data`](https://github.com/hoardcti/c2-infrastructure/tree/data) branch as one JSON file per IP, laid out as described in [Output](#output).

```bash
curl -fsSL https://raw.githubusercontent.com/hoardcti/c2-infrastructure/data/ipv4/1/15/76/39.json
```

Fetch the whole dataset:

```bash
git clone --branch data --single-branch --depth 1 https://github.com/hoardcti/c2-infrastructure.git c2-infrastructure-data
```

## Configuration

[`sources.json`](sources.json) lists every source under `aggregator.feeds` or `aggregator.enrichers`, in the order they run. Feeds run first, so enrichers also see the IPs they add.

```json
{
    "name": "virustotal",
    "enabled": true,
    "url": "https://www.virustotal.com/api/v3/ip_addresses/",
    "requests_per_minute": 4,
    "max_lookups": 20,
    "refresh_after_hours": 720,
    "max_minutes_per_run": 6
}
```

| Setting | Applies to | Meaning |
|---|---|---|
| `name` | All | Selects the source's package, and names its history in every record. |
| `enabled` | All | Whether the source runs. Required. |
| `url` | All | The upstream endpoint; must be `https`. |
| `requests_per_minute` | All | Rate limit for the source's requests, retries included. |
| `max_lookups` | Enrichers | IPs looked up per run. With hourly runs, 24 × `max_lookups` must stay within any daily quota. |
| `refresh_after_hours` | Enrichers | How long before an IP is looked up again. |
| `max_minutes_per_run` | Enrichers | Time budget per run, so a slow upstream can't hold the run up. |
| `options` | Some sources | Source-specific settings, such as ThreatFox's query or AbuseIPDB's `max_age_in_days`. |

Unknown settings are refused at start-up, so typos are caught before any work starts.

Enrichers look up IPs never checked by them first, newest `first_seen` first, then the IPs waiting longest since their last check. The defaults keep every free quota safe: VirusTotal looks up 20 IPs an hour (480 of its 500 a day) and AbuseIPDB 40 (960 of its 1,000). A full pass over the dataset takes days for the strictest quotas, and then only new and due IPs are looked up.

### Rate limits and failures

- Each source has its own rate limiter. `429`, `502`, `503` and `504` responses are retried up to three times with exponential backoff and jitter, honouring `Retry-After`. A `Retry-After` longer than two minutes means a quota is used up and isn't waited for.
- A source that fails doesn't stop the others.
- Every failure is classified by what it means, not just its status code. Sources map upstream quirks onto the same meanings, such as abuse.ch's `unknown_auth_key` in a `200` response, or Shodan's per-host `403`:

  | Meaning | Typical response | What happens |
  |---|---|---|
  | Key rejected | `401`, abuse.ch `unknown_auth_key` | The source stops for the rest of the run; the error says to check the key. Nothing is recorded on the IP. |
  | Plan doesn't allow it | `402`, `403` | The source stops; the error says to upgrade the plan or disable the source. |
  | Quota used up | `429` after retries | The source stops; the error says to lower `max_lookups` or `requests_per_minute`. |
  | Nothing known | `404`, `no_results` | Not a failure: the IP is marked as checked, with no observation. |
  | This IP refused | Other `4xx` such as AbuseIPDB's `422`, Shodan's `403` for a host the free plan doesn't cover, URLhaus `invalid_host` | Recorded as `last_error` on the IP and logged as a warning; the run carries on and doesn't fail. |
  | Upstream unavailable | `5xx`, timeouts, broken connections | Recorded as `last_error` on the IP and retried when it's next due. Five in a row stop the source. |

- An enricher also stops quietly when its time budget runs out, leaving the rest for the next run.
- The run exits with `1` if any source failed (anything but the expected answers above), after storing everything the other sources reported, so the workflow still publishes it.
- API keys are never logged, never put in errors, and removed from upstream error messages. Shodan only accepts its key in the URL, so URLs in errors never include their query.

## Development

Put your keys in a `.env` file (see [`.env.example`](.env.example) and [`KEY.md`](KEY.md)):

```bash
ABUSECH_API_KEY=your-key
```

```bash
# Build bin/aggregator and run it
make build
./bin/aggregator

# Run every check CI runs: tidy, format, lint, go fix, tests with 100% coverage, govulncheck, build
make check

# List the other targets
make help
```

`aggregator` takes `-sources` (default `sources.json`), `-out` (default `out`), `-env` (default `.env`), `-log` (`text` or `json`) and `-level` (`debug`, `info`, `warn` or `error`); `./bin/aggregator -h` describes them. It exits with 0 on success, 1 when a source fails and 2 on a usage or configuration error.

The code follows the [hoardCTI Go style guide](https://style.hoardcti.com/v1/golang/); see [`AGENTS.md`](AGENTS.md) for the house rules that differ from common Go style. Tests never call real upstreams: each source is tested against recorded responses served by a local TLS server. The fixtures and their origins are listed in [`internal/aggregator/testdata/README.md`](internal/aggregator/testdata/README.md).

### Layout

```
cmd/aggregator/                 Command: flags, environment, wiring of the enabled sources
internal/aggregator/            Core: records and history, storage, scheduling, Upstream HTTP client
internal/aggregator/<source>/   One package per source: client, parsing, data types, tests, fixtures
internal/aggregator/fakeupstream/  Fake upstream server shared by the source packages' tests
```

### Adding a source

1. Create `internal/aggregator/<name>/` with a `SOURCE_NAME` constant and a `New` constructor taking the `aggregator.SourceConfig` and an `*aggregator.Upstream` (plus a key if it needs one).
2. Implement `Collect(ctx) ([]aggregator.Sighting, error)` for a feed or `Lookup(ctx, address) ([]aggregator.Report, error)` for an enricher. Send requests with `Upstream.Fetch`, which handles rate limiting, retries and body limits; build reports with `aggregator.NewReport`, from a typed `Data` struct with `snake_case` JSON tags. Leave out fields that change on every lookup, sort lists whose order means nothing, and give each report a `key` if the source reports several things per IP.
3. Test it against recorded responses with `fakeupstream`, fuzz its parsing, and list the fixtures in the testdata README. `make check` requires 100% coverage.
4. Register it in `newFeedOption` or `newEnricherOption` in [`cmd/aggregator/main.go`](cmd/aggregator/main.go), and its key's variable in `credentialVariables`.
5. Add it to `sources.json`, its key to `.env.example`, `KEY.md` and the workflow, and a row to the table above.

Never commit keys. Supply them through environment variables or `.env` only.

## Licence

Licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE).

Data from upstream sources stays under each source's terms; see [`research.md`](research.md) and [`KEY.md`](KEY.md).

- [ThreatFox](https://threatfox.abuse.ch/), [Feodo Tracker](https://feodotracker.abuse.ch/) and [URLhaus](https://urlhaus.abuse.ch/) (abuse.ch) data is published under CC0.
- IP data from [IPinfo](https://ipinfo.io/) Lite is licensed under CC BY-SA 4.0.
- DROP data is © [The Spamhaus Project](https://www.spamhaus.org/).
- Port and service data from [Shodan](https://www.shodan.io/) InternetDB and the Shodan API.
- Enrichment from [VirusTotal](https://www.virustotal.com/), [AbuseIPDB](https://www.abuseipdb.com/) and [AlienVault OTX](https://otx.alienvault.com/) is used under their free, non-commercial terms.
