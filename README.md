# c2-infrastructure

Collects command and control (C2) server IPs from public threat intelligence sources and emits them as normalised Hoard CTI records.

![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhoardcti%2Fc2-infrastructure%2Frefs%2Fheads%2Fmain%2Fstats.json&query=servers&label=C2%20Servers&color=A1BC98&style=flat-square) ![Dynamic JSON Badge](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fhoardcti%2Fc2-infrastructure%2Frefs%2Fheads%2Fmain%2Fstats.json&query=last_edit&label=Last%20Updated&color=A1BC98&style=flat-square)

## Overview

Security tooling often needs to answer one question quickly: *is this IP a known C2 server, and what is it running?* Public trackers publish this data in different formats, field names and timestamp conventions, so every consumer ends up writing the same parsers.

[`c2-infrastructure`](https://github.com/hoardcti/c2-infrastructure) is a Hoard CTI source module. It pulls C2 indicators from upstream trackers every hour and stores each IP as its own JSON file, merging sightings from every source that reports it.

It records what public feeds report. It does not scan, probe or connect to the listed servers.

It is intended for:

- **Hoard CTI operators** running the aggregation platform
- **Defenders and tool authors** who want a normalised, pull-based C2 IP feed without writing per-source integrations

### Sources

| Source | Status | Data |
|---|---|---|
| [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) | Active | `ip:port` IOCs tagged `c2`: malware family, port, threat type, first seen, Malpedia link, reference |
| [Feodo Tracker (abuse.ch)](https://feodotracker.abuse.ch/) | Disabled | Botnet C2 blocklist: malware family, port, country, hostname, first seen, last online |
| [ViriBack C2 Tracker](https://tracker.viriback.com/) | Disabled | C2 panels from the last 30 days: family, panel URL, first seen |
| [Criminal IP C2 Daily Feed](https://github.com/criminalip/C2-Daily-Feed) | Disabled | Daily C2 list: family, port, score, country, scan time |

Disabled sources are implemented and tested but switched off with `"enabled": false` in [`sources.json`](sources.json).

### Output

Each IP is written to its own JSON file in a directory tree that mirrors the address. IPv6 addresses use their fully expanded form:

```
ipv4/1/15/76/39.json
ipv6/2001/0db8/85a3/0000/0000/8a2e/0370/7334.json
```

A record holds the union of all flags (lowercased malware families) and one result per source and flag set. When a source reports an IP again, its result is refreshed but keeps the `datetime` it was first collected:

```json
{
    "ip": "1.15.76.39",
    "flags": ["cobalt strike"],
    "results": [
        {
            "source": "threatfox",
            "datetime": "2026-09-23T17:37:10.920637",
            "flags": ["cobalt strike"],
            "metadata": {
                "firstSeen": "2026-09-14T11:11:41",
                "ioc": "1.15.76.39:50050",
                "port": "50050",
                "threat_type": "botnet_cc"
            }
        }
    ]
}
```

`datetime` is when this module collected the result. Timestamps are ISO 8601 without a timezone offset; the hosted workflow runs in UTC. `metadata` fields vary by source.

## Installation

This module is designed to run on GitHub Actions workers, so there is nothing to install to consume its data. The workflow in [`.github/workflows/`](.github/workflows/) builds and runs it every hour, commits the records to the `data` branch and updates [`stats.json`](stats.json) on `main`.

To run it on a fork, add these repository secrets:

| Secret | Purpose |
|---|---|
| `ABUSECH_API_KEY` | abuse.ch Auth-Key, from the [abuse.ch authentication portal](https://auth.abuse.ch/) |
| `BOT_PAT` | Token with write access, used to push to the `data` and `main` branches |

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

## Development

Put your Auth-Key in a `.env` file (see [`.env.example`](.env.example)):

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

The code follows the [hoardCTI Go style guide](https://style.hoardcti.com/v1/golang/); see [`AGENTS.md`](AGENTS.md) for the house rules that differ from common Go style.

Sources are configured in [`sources.json`](sources.json). To add one, write an extractor in [`internal/aggregator/`](internal/aggregator/), register it under the source's name in `New` ([`aggregator.go`](internal/aggregator/aggregator.go)), and add the source to `sources.json` with `"enabled": true`.

Never commit Auth-Keys. Supply them through environment variables or `.env` only.

## Licence

Licensed under the GNU General Public License v3.0 — see [LICENSE](LICENSE).

- [ThreatFox (abuse.ch)](https://threatfox.abuse.ch/) data is published under CC0.
