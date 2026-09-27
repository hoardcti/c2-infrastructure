# Test fixtures

Sample upstream data and published output used by the `aggregator` tests. Upstream
files are kept byte for byte as downloaded, apart from being shortened.

| File | Source | Collected |
|---|---|---|
| `criminalip.csv` | First 5 rows of Criminal IP's [C2 Daily Feed](https://github.com/criminalip/C2-Daily-Feed) | 2026-09-27 |
| `feodotracker.json` | Feodo Tracker's [recommended IP blocklist](https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json), complete | 2026-09-27 |
| `viribacktracker.csv` | First 5 rows of the [ViriBack C2 tracker](https://tracker.viriback.com/last30.php) | 2026-09-27 |
| `threatfox_taginfo.json` | A ThreatFox `taginfo` response rebuilt from three indicators published on the `data` branch, plus a made-up domain indicator (`c2.evil.example`). The live API needs an Auth-Key, so no response was captured. The `reporter` field is redacted. | 2026-09-27 |
| `published_threatfox.json` | `ipv4/155/94/154/152.json` from the `data` branch, written by the Go aggregator | 2026-09-27 |
| `published_criminalip.json` | `ipv4/99/209/179/82.json` from the `data` branch, written by the earlier Python aggregator (keys in insertion order, no final newline) | 2026-09-27 |

The IP addresses are public threat-intelligence indicators, and the files contain no
credentials or personal data.
