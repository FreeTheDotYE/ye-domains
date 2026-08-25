# Archive and manifest format

## WARC records

Each `archives/warc/<domain>.warc.gz` file contains exactly one independently
compressed WARC 1.0 `response` record. Independent files make individual
archives directly downloadable and keep every object below normal Git hosting
limits.

The WARC header set is intentionally small:

| Field | Meaning |
| --- | --- |
| `WARC-Type` | Always `response`. |
| `WARC-Target-URI` | Public root URL returned by the archived server. |
| `WARC-Date` | Fixed privacy sentinel, never an acquisition timestamp. |
| `WARC-Record-ID` | Deterministic UUID derived from the sanitized record. |
| `WARC-Block-Digest` | Base32 SHA-1 digest of the HTTP message block. |
| `WARC-Payload-Digest` | Base32 SHA-1 digest of the response body. |
| `Content-Type` | Always `application/http; msgtype=response`. |
| `Content-Length` | Exact HTTP message-block byte length. |

SHA-1 is used only for conventional WARC interoperability. The repository-level
`archives/SHA256SUMS` file and manifest provide SHA-256 integrity values.

The gzip header has no filename, comment, extra field, or timestamp. Its OS byte
is normalized to `255`, and maximum compression is used. These choices make the
archive bytes reproducible across builds.

## Sanitized HTTP metadata

The HTTP status line, response body, and stable response metadata are retained.
Collection-bound fields are excluded. The excluded categories are:

- response and expiration times that can reveal the request moment;
- cookies or authorization state;
- request, trace, CDN-ray, and session identifiers;
- client IP, forwarding, and proxy metadata;
- request-specific rate-limit and timing state;
- hop-by-hop transport metadata; and
- archive-tool transformation metadata.

`Content-Length` is recalculated after header normalization. Payload bytes are
not rewritten, decoded, interpreted, or filtered.

## Manifest

`archives/manifest.csv` is UTF-8 with an LF line ending and these columns:

| Column | Definition |
| --- | --- |
| `schema_version` | Manifest schema, currently `1`. |
| `domain` | Lowercase `.ye` hostname and archive filename stem. |
| `target_url` | Root HTTP(S) URL represented by the WARC record. |
| `http_status` | Three-digit status code from the archived response. |
| `media_type` | Normalized media type, without parameters; blank if absent. |
| `compressed_bytes` | Size of the deterministic `.warc.gz` file. |
| `uncompressed_bytes` | Size of the complete uncompressed WARC record. |
| `payload_bytes` | Response-body size. |
| `warc_sha256` | SHA-256 of the complete compressed archive. |
| `payload_sha256` | SHA-256 of the unchanged response body. |
| `warc_record_id` | Deterministic public WARC record identifier. |

Rows are sorted bytewise by `domain`. There is exactly one row and one archive
per domain. `archives/summary.json` repeats aggregate counts so consumers can make
quick completeness checks without parsing every WARC.

## Time interpretation

The only `WARC-Date` value is the documented sentinel
`1970-01-01T00:00:00Z`. Filesystem times, Git commit times, release times, and
the sentinel describe publication or normalization mechanics, not acquisition.
No public field can be used as a reliable capture date.
