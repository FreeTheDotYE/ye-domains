# Public data dictionary

## data/domains.csv

One row per retained registrable domain.

- `domain`: normalized ASCII/IDNA form.
- `unicode_domain`: Unicode display form when IDNA decoding is available.
- `public_suffix`: one of `ye`, `com.ye`, `edu.ye`, `gov.ye`, `mil.ye`, `net.ye`, or `org.ye`.
- `registration_level`: `direct_under_ye` or `under_structured_suffix`.

## data/hostnames.csv

One row per retained hostname.

- `hostname`: normalized ASCII/IDNA hostname.
- `unicode_hostname`: Unicode display form.
- `registrable_domain`: matching row in `data/domains.csv`.

## data/registration.jsonl

One JSON object per domain for which a safe registration record could be normalized. Values from duplicate records are collapsed into sorted unique arrays.

- `schema_version`: public schema version.
- `domain`: matching registrable domain.
- `registry_ids_observed`: non-contact registry object identifiers.
- `statuses_observed`: normalized domain status values.
- `nameservers_observed`: normalized nameserver hostnames.
- `delegation_signed_observed`: observed Boolean DNSSEC delegation states.
- `zone_signed_observed`: observed Boolean zone-signing states.
- `registration_dates_observed`: domain registration dates at day precision.
- `expiration_dates_observed`: domain expiry dates at day precision.
- `last_changed_dates_observed`: domain-record change dates at day precision.

The lifecycle dates above are facts carried by domain registration records. Acquisition timestamps, database-refresh timestamps, contact cards, entity cards, email addresses, telephone numbers, postal addresses, provider links, and raw responses are excluded.

## Monitoring outputs

The `monitoring` directory contains day-precision run summaries, confirmed DNS state, confirmed change events, discovered hostnames, and a separate Sohobcom DNS infrastructure view.

### monitoring/state.jsonl

Each row identifies a hostname, its registrable domain, and a complete `dns` object. The DNS object contains `status`, `a`, `aaaa`, `cname`, `ns`, `mx`, `soa_mname`, `soa_serial`, `ds`, and `dnskey`. A `records_present` status always has at least one record value; `no_records`, `nxdomain`, and `unobserved` states have none.

### monitoring/events

Confirmed field changes are stored as month-partitioned JSON Lines. Public events contain only a calendar date, hostname, changed field, before and after values, a review classification, and an identifier derived from that public payload.

### monitoring/sohobcom-dns.json

This state-derived view contains:

- `sohobcom_zone_records`: records for the Sohobcom apex and observed names below it.
- `authoritative_mail_targets`: the apex nameserver, SOA authority, and mail-exchange targets.
- `related_dns_records`: records for those exact authority or mail target hostnames when they are present in monitor state.
- `apex_addresses`: A and AAAA values on the Sohobcom apex only.
- `technical_overlaps`: per-domain intersections with the authority/mail targets, references to the Sohobcom namespace, or shared apex addresses.

Historical collection provenance is not mixed into automated run dates. Technical overlap is evidence of an infrastructure relationship only, not proof of ownership, affiliation, intent, or wrongdoing.
