# Public data dictionary

## data/domains.csv

One row per retained registrable domain.

- `domain`: normalized ASCII/IDNA form.
- `unicode_domain`: Unicode display form when IDNA decoding is available.
- `public_suffix`: `ye` or a recognized structured level: `biz.ye`, `com.ye`, `edu.ye`, `gov.ye`, `hospital.ye`, `law.ye`, `me.ye`, `mil.ye`, `net.ye`, `org.ye`, `pro.ye`, `school.ye`, `tv.ye`, or `uni.ye`.
- `registration_level`: `direct_under_ye` or `under_structured_suffix`. Structured-level names can also remain direct-under-`.ye` rows when independently retained in the historical corpus.

## data/hostnames.csv

One row per retained hostname.

- `hostname`: normalized ASCII/IDNA hostname.
- `unicode_hostname`: Unicode display form.
- `registrable_domain`: matching row in `data/domains.csv`, using the longest recognized registry level.

## data/registration.jsonl

One JSON object per domain for which a safe registration record could be normalized. Values from duplicate records are collapsed into sorted unique arrays.

- `schema_version`: public schema version.
- `domain`: matching registrable domain.
- `registry_ids_observed`: non-contact registry object identifiers.
- `statuses_observed`: normalized source status tokens explicitly present in safe registration records; semantically related statuses are not inferred.
- `nameservers_observed`: normalized nameserver hostnames.
- `delegation_signed_observed`: observed Boolean DNSSEC delegation states.
- `zone_signed_observed`: observed Boolean zone-signing states.
- `registration_dates_observed`: domain registration dates at day precision.
- `expiration_dates_observed`: domain expiry dates at day precision.
- `last_changed_dates_observed`: domain-record change dates at day precision.

The lifecycle dates above are facts carried by domain registration records. Acquisition timestamps, database-refresh timestamps, contact cards, entity cards, email addresses, telephone numbers, postal addresses, provider links, and raw responses are excluded.

## Public webpage archives

The `archives` directory contains privacy-normalized WARC records for archived
root-page responses. Each archived domain must also exist as a registrable
domain in `data/domains.csv`.

### archives/warc/<domain>.warc.gz

One deterministic gzip-compressed WARC/1.0 `response` record per file.

- The filename is the matching ASCII `domain` from `data/domains.csv`.
- `WARC-Target-URI` is the archived root URL.
- `WARC-Date` is the documented sentinel
  `1970-01-01T00:00:00Z`; it is not a capture-time claim.
- `WARC-Record-ID`, WARC block and payload digests, content lengths, and the
  gzip container are generated deterministically.
- The embedded HTTP status line and response payload are preserved. Acquisition
  headers and other collector-correlating metadata are removed.

Each file contains one response only. It is not a recursive crawl and does not
imply that the domain is currently registered, reachable, or controlled by the
same party.

### archives/manifest.csv

One row per file in `archives/warc`, sorted by `domain`.

- `schema_version`: archive manifest schema version.
- `domain`: matching registrable domain in `data/domains.csv`.
- `target_url`: matching WARC target root URL.
- `http_status`: preserved three-digit HTTP response status.
- `media_type`: normalized response media type, without parameters.
- `compressed_bytes`: gzip-compressed file length.
- `uncompressed_bytes`: uncompressed WARC record length.
- `payload_bytes`: embedded HTTP response-body length.
- `warc_sha256`: SHA-256 digest of the complete `.warc.gz` file.
- `payload_sha256`: SHA-256 digest of the preserved response body.
- `warc_record_id`: deterministic WARC record identifier.

### archives/summary.json

Aggregate counts and policies derived from the manifest and WARC files.

- `schema_version` and `scope`: public summary schema and archive boundary.
- `archive_count`, `distinct_domains`, `distinct_target_urls`, and
  `distinct_payloads`: archive and distinct-value counts.
- `compressed_bytes`, `uncompressed_bytes`, and `payload_bytes`: package totals.
- `http_statuses`, `http_status_classes`, and `media_types`: derived response
  distributions.
- `warc_version`, `record_type`, and `records_per_file`: record structure.
- `capture_time_policy`: sentinel-date policy and rationale.
- `response_payload_policy`: preservation rule for embedded response bodies.

### archives/SHA256SUMS

Deterministic SHA-256 checksums for every public WARC plus the manifest and
summary. The validator requires exact coverage and bytewise agreement.

The WARC payloads reproduce third-party public content and are not placed under
CC0. See `archives/RIGHTS.md` and `DATA-LICENSE.md` for rights and reuse limits.

## Monitoring outputs

The `monitoring` directory contains day-precision run summaries, confirmed DNS state, confirmed change events, discovered hostnames, and a separate Sohobcom DNS infrastructure view.

### monitoring/state.jsonl

Each row identifies a hostname, its longest-match registrable domain, and a complete `dns` object. The DNS object contains `status`, `a`, `aaaa`, `cname`, `ns`, `mx`, `soa_mname`, `soa_serial`, `ds`, and `dnskey`. A `records_present` status always has at least one record value; `no_records`, `nxdomain`, and `unobserved` states have none.

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
