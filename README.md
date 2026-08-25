# Yemen .ye Domain Observatory

This repository is a privacy-minimized research corpus of observed and historical domain names and hostnames under Yemen's `.ye` country-code namespace.

It retains valid names even when they are no longer registered, delegated, reachable, or in use. Inclusion therefore means that a name appeared in the research corpus; it does not mean that the name is currently registered or controlled by any particular person or organization.

## Current public corpus

- 1,482 registrable domains
- 4,722 hostnames
- 1,371 domains with deduplicated, non-personal registration signals
- 111 historical domains retained without a clean registration record

The corpus combines multiple public datasets and technical observations. Detailed source identities, acquisition order, and historical collection timestamps are withheld for collector safety. That safety choice limits independent reproduction and must be considered when using the dataset.

## Files

- `data/domains.csv`: every retained registrable domain.
- `data/hostnames.csv`: every retained hostname, including historical and inactive names.
- `data/registration.jsonl`: deduplicated domain-level registration signals with contact and entity data removed.
- `data/summary.json`: reconciled counts and privacy flags.
- `analysis/public_suffix_distribution.csv`: distribution across the public `.ye` namespace levels.
- `monitoring/`: sanitized DNS state, confirmed changes, and a technical Sohobcom DNS-overlap view.

Registration lifecycle dates in `registration.jsonl` describe the domain record itself and are reduced to calendar-day precision. They are not acquisition timestamps.

## DNS monitoring

A private automated job publishes sanitized DNS state and confirmed changes for the complete hostname inventory. The public output covers A, AAAA, CNAME, NS, MX, SOA, and delegation/DNSSEC signals where applicable. It also records technical overlaps involving Sohobcom-related DNS infrastructure because Sohobcom presents itself as a hosting provider.

The Sohobcom view separates records within the Sohobcom namespace, apex authority and mail targets, records for those exact targets, apex addresses, and overlaps found elsewhere in the corpus. This makes the hosting-infrastructure evidence inspectable without turning a technical relationship into an attribution claim.

The monitor is limited to DNS observation and does not conduct active network or application-security testing. A changed DNS field must be seen in two consecutive definitive runs before it replaces committed state.

Technical overlap can show shared addresses, nameservers, mail routing, authority infrastructure, or references into the Sohobcom namespace. It does not by itself prove ownership, organizational affiliation, political alignment, intent, or wrongdoing.

## Research purpose

The dataset supports historical documentation, namespace-governance research, infrastructure-change monitoring, and study of how `.ye` domains and hosting infrastructure are used in the context of conflict and contested telecommunications governance.

This is not an official registry zone file and cannot be treated as a complete list of every name ever registered under `.ye`.

## Validate

The public validator uses only the Python standard library:

```sh
python scripts/validate_dataset.py
```

## Licensing

Code is MIT licensed. The normalized factual compilation is released under the terms in [DATA-LICENSE.md](DATA-LICENSE.md). No rights are claimed over third-party personal data or raw responses, which are not published.
