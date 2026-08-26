# Yemen .ye Domain Observatory

This repository is a privacy-minimized research corpus and public-page archive for Yemen's `.ye` country-code namespace.

It retains valid names even when they are no longer registered, delegated, reachable, or in use. Inclusion therefore means that a name appeared in the research corpus; it does not mean that the name is currently registered or controlled by any particular person or organization.

## Current public corpus

- 1,489 registrable domains
- 4,724 hostnames
- 1,377 domains with deduplicated, non-personal registration signals
- 112 historical domains retained without a clean registration record
- 219 privacy-normalized homepage WARC response records

The corpus combines multiple public datasets and technical observations. Detailed source identities, acquisition order, and historical collection timestamps are withheld for collector safety. That safety choice limits independent reproduction and must be considered when using the dataset.

## Files

- `data/domains.csv`: every retained registrable domain.
- `data/hostnames.csv`: every retained hostname, including historical and inactive names.
- `data/registration.jsonl`: deduplicated domain-level registration signals with contact and entity data removed.
- `data/summary.json`: reconciled counts and privacy flags.
- `analysis/public_suffix_distribution.csv`: distribution across the public `.ye` namespace levels.
- `monitoring/`: sanitized DNS state, confirmed changes, and a technical Sohobcom DNS-overlap view.
- `evidence/common-crawl/`: historical web-capture references and domain/hostname discovery summaries.
- `evidence/tls/`: deployed TLS observations plus content-addressed certificate files.
- `evidence/infrastructure/`: an append-only relationship graph linking domains, hosts, DNS, addresses, routing, registrars, web captures, and certificates.
- `archives/warc/`: one privacy-normalized WARC response per archived `.ye` homepage.
- `archives/manifest.csv`: searchable archive metadata, sizes, identifiers, and SHA-256 values.
- `archives/summary.json`: reconciled WARC coverage, status classes, media types, and byte counts.
- `archives/SHA256SUMS`: integrity checks for every loose WARC plus the archive manifest and summary.

Registration lifecycle dates in `registration.jsonl` describe the domain record itself and are reduced to calendar-day precision. They are not acquisition timestamps.

Cleaned companion registration data is maintained in [FreeTheDotYE/ye-rdap-whois](https://github.com/FreeTheDotYE/ye-rdap-whois); its stable snapshot is available as [v1.1.0](https://github.com/FreeTheDotYE/ye-rdap-whois/releases/tag/v1.1.0).

Hostname mappings use the longest recognized registry level. Registry-delegated structured levels are documented in the data dictionary; the current corpus includes child registrations under `hospital.ye`, `law.ye`, `school.ye`, and `uni.ye`. Level names themselves remain retained direct-under-`.ye` corpus entries where historically observed.

## Public WARC archive

The archive includes every homepage WARC currently available to the project: 219 distinct `.ye` root URLs with one public HTTP response record each. Response payload bytes are preserved exactly, including redirects, errors, and empty bodies.

Contributor-safety normalization removes collection-bound timestamps, cookies, per-request identifiers, forwarding data, rate-limit state, hop-by-hop transport fields, and tool-added archive metadata. Each public record uses `1970-01-01T00:00:00Z` as an explicit `WARC-Date` privacy sentinel; it is not an acquisition timestamp. Stable public response metadata such as `Last-Modified` can remain because it describes the resource rather than the collection event.

These are homepage responses, not recursive crawls. An archived response does not establish a site's current state, ownership, control, affiliation, intent, or wrongdoing. Preserved public content may contain dates, identifiers, or personal information published by the originating site, and can be correlated by someone who already holds another copy. Pre-normalization originals remain in restricted preservation storage.

See [`archives/README.md`](archives/README.md), [`archives/format.md`](archives/format.md), and [`archives/RIGHTS.md`](archives/RIGHTS.md) for format, interpretation, and third-party rights guidance. Download the timeless [`warc-v1` release](https://github.com/FreeTheDotYE/ye-domains/releases/tag/warc-v1), its [WARC bundle](https://github.com/FreeTheDotYE/ye-domains/releases/download/warc-v1/ye-homepage-warcs-v1.tar.zst), or the bundle's [SHA-256 checksum](https://github.com/FreeTheDotYE/ye-domains/releases/download/warc-v1/ye-homepage-warcs-v1.tar.zst.sha256). The same asset can be reproduced outside the repository with:

```sh
node scripts/warc-bundle.mjs . ../ye-warcs-release-assets
```

## DNS monitoring

A private automated job publishes sanitized DNS state and confirmed changes for the complete hostname inventory. The public output covers A, AAAA, CNAME, NS, MX, SOA, and delegation/DNSSEC signals where applicable. It also records technical overlaps involving Sohobcom-related DNS infrastructure because Sohobcom presents itself as a hosting provider.

The Sohobcom view separates records within the Sohobcom namespace, apex authority and mail targets, records for those exact targets, apex addresses, and overlaps found elsewhere in the corpus. This makes the hosting-infrastructure evidence inspectable without turning a technical relationship into an attribution claim.

The monitor is limited to DNS observation and does not conduct active network or application-security testing. A changed DNS field must be seen in two consecutive definitive runs before it replaces committed state.

Technical overlap can show shared addresses, nameservers, mail routing, authority infrastructure, or references into the Sohobcom namespace. It does not by itself prove ownership, organizational affiliation, political alignment, intent, or wrongdoing.

## Historical web, TLS, and infrastructure evidence

The generated `evidence/` tree adds three independently inspectable layers. Common Crawl records supply historical capture dates and WARC byte-range references while also expanding the known structured-suffix domain inventory. Deployed TLS observations preserve the exact public leaf certificate returned by a normal port 443 handshake and track certificate changes over time. The infrastructure graph joins these observations to current DNS, routing origin, and cleaned registration signals with first-seen, last-seen, active-state, and provenance-class fields.

Public records use calendar-day precision. Common Crawl URL paths and query strings are represented by SHA-256 values; the public record retains the hostname, registrable domain, capture metadata, public content digest, and WARC reference needed for future retrieval. Connection failures remain private because a failed attempt is not evidence that a service is absent.

Graph edges are technical observations. Shared infrastructure can prioritize archival and research review, but it does not alone establish control, ownership, affiliation, intent, or wrongdoing.

## Research purpose

The dataset supports historical documentation, namespace-governance research, infrastructure-change monitoring, and study of how `.ye` domains and hosting infrastructure are used in the context of conflict and contested telecommunications governance.

This is not an official registry zone file and cannot be treated as a complete list of every name ever registered under `.ye`.

## Validate

The corpus validator uses the Python standard library. WARC validation and tests require Node.js 20 or newer:

```sh
python scripts/validate_dataset.py
python scripts/validate_tracking.py evidence
node --test tests/warc-*.test.mjs
node scripts/warc-validate.mjs .
sha256sum -c archives/SHA256SUMS
```

## Licensing

Code is MIT licensed. The normalized factual compilation and archive metadata are released under the terms in [DATA-LICENSE.md](DATA-LICENSE.md). Archived response content remains subject to third-party rights and is not placed under CC0; see [`archives/RIGHTS.md`](archives/RIGHTS.md).
