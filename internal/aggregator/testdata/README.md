# Test fixtures

Sample upstream data and stored records used by the tests. Each source package keeps its
fixtures in its own `testdata/` directory; this file lists all of them. Upstream files are
kept as received apart from being shortened, with personal data removed where noted.

The IP addresses are public threat-intelligence indicators. No file contains a credential;
every response was checked for the keys used to fetch it.

## Stored records (`internal/aggregator/testdata/`)

| File | Content | Collected |
|---|---|---|
| `published_threatfox.json` | `ipv4/155/94/154/152.json` from the `data` branch: a version 1 record written by the Go aggregator | 2026-09-27 |
| `published_criminalip.json` | `ipv4/99/209/179/82.json` from the `data` branch: a version 1 record written by the earlier Python aggregator (keys in insertion order, no final newline) | 2026-09-27 |

## Feeds

| File | Source | Collected |
|---|---|---|
| `threatfox/testdata/taginfo.json` | A ThreatFox `taginfo` response rebuilt from three indicators published on the `data` branch, plus a made-up domain indicator (`c2.evil.example`). The `reporter` field is redacted. | 2026-09-27 |
| `feodotracker/testdata/ipblocklist_recommended.json` | Feodo Tracker's [recommended IP blocklist](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json), complete | 2026-09-27 |
| `viribacktracker/testdata/last30.csv` | First 5 rows of the [ViriBack C2 tracker](https://tracker.viriback.com/last30.php) | 2026-09-27 |
| `criminalip/testdata/2026-09-24.csv` | First 5 rows of Criminal IP's [C2 Daily Feed](https://github.com/criminalip/C2-Daily-Feed) | 2026-09-27 |

## Enrichers

| File | Source | Collected |
|---|---|---|
| `internetdb/testdata/1.15.76.39.json` | InternetDB response for a Cobalt Strike server, complete | 2026-10-01 |
| `internetdb/testdata/not_found.json` | InternetDB's 404 body for an unknown address, complete | 2026-10-01 |
| `ipinfo/testdata/1.15.76.39.json` | IPinfo Lite response, complete | 2026-10-01 |
| `abuseipdb/testdata/1.15.76.39.json` | AbuseIPDB `check` response without verbose reports, complete | 2026-10-01 |
| `urlhaus/testdata/110.136.50.184.json` | URLhaus host response for a host from the recent-URLs list. The `reporter` field is redacted. | 2026-10-01 |
| `urlhaus/testdata/no_results.json` | URLhaus host response for an unknown host, complete | 2026-10-01 |
| `virustotal/testdata/1.15.76.39.json` | VirusTotal IP report with `whois`, `rdap` and `whois_date` removed (they hold personal contact details), vendor verdicts shortened to six, and partner note details cut to 120 characters | 2026-10-01 |
| `otx/testdata/1.117.77.166.json` | OTX `general` section with two of nine pulses, without their `author`, `description`, `references` and `groups` fields | 2026-10-01 |
| `shodan/testdata/1.15.76.39.json` | Shodan host response with three of eight banners, without raw banner text, HTML, certificate chains or HTTP details other than the status, title and server | 2026-10-01 |
| `spamhaus/testdata/drop_v4.json`, `drop_v6.json` | First 5 netblocks and the metadata line of each [DROP list](https://www.spamhaus.org/drop/) | 2026-10-01 |
