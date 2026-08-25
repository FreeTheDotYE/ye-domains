# Public `.ye` homepage WARC collection

This archive collection preserves every homepage WARC currently available to the
FreeTheDotYE project: **219 archives for 219 distinct `.ye` hostnames**. Each
file contains one public HTTP response record for the root URL of its hostname.

The collection is intended for historical research, reproducibility, and
independent study of the `.ye` namespace. It is not a live-site scanner and it
does not establish who owns, operates, or controls a domain.

## What is preserved

- All 219 public target URLs.
- The HTTP status line and non-volatile public response headers.
- Every response payload byte exactly as held by the project, including empty
  bodies and error or redirect responses.
- Valid WARC block and payload digests.
- A deterministic manifest and SHA-256 checksums.

The collection contains 128 successful (2xx) responses, 73 redirects (3xx), 11 `404`
responses, 1 `403`, and 6 `500` responses. A response code describes the
archived response only; it is not a claim about the site's present state.

## Contributor-safety normalization

The project assembled its historical corpus from multiple public methods and
datasets. Exact acquisition sources, ordering, and times are not published in
order to protect contributors.

Response bodies are unchanged. Collection-bound metadata is removed or
normalized, including exact capture timestamps, cookies, per-request IDs,
client/proxy forwarding data, rate-limit state, hop-by-hop transport fields,
and tool-added archive headers. Server content dates such as `Last-Modified`
are retained because they describe the public resource rather than the
collection event.

Every public WARC uses `1970-01-01T00:00:00Z` as an explicit sentinel value for
`WARC-Date`. It is **not** the acquisition time and must never be interpreted as
one. The original records remain in restricted private preservation storage.

## Layout

```text
archives/warc/           one deterministic .warc.gz file per hostname
archives/manifest.csv    one searchable row per archive
archives/summary.json    aggregate coverage and format information
archives/format.md       field definitions and interpretation notes
archives/RIGHTS.md       rights and responsible-use notice
scripts/warc-*.mjs       sanitizer, bundle generator, and validator
tests/warc-*.test.mjs    offline privacy and integrity tests
archives/SHA256SUMS      checksums for archives and archive data files
```

The [`warc-v1` GitHub release](https://github.com/FreeTheDotYE/ye-domains/releases/tag/warc-v1)
also provides the timeless convenience asset
[`ye-homepage-warcs-v1.tar.zst`](https://github.com/FreeTheDotYE/ye-domains/releases/download/warc-v1/ye-homepage-warcs-v1.tar.zst)
and its
[SHA-256 sidecar](https://github.com/FreeTheDotYE/ye-domains/releases/download/warc-v1/ye-homepage-warcs-v1.tar.zst.sha256).
It contains the same validated loose archives, manifest, summary,
documentation, and checksums.

## Verification

Node.js 20 or newer is sufficient for tests and loose-archive validation.
Creating the optional `.tar.zst` release asset additionally requires the `zstd` CLI.

```sh
node --test tests/warc-*.test.mjs
node scripts/warc-validate.mjs .
sha256sum -c archives/SHA256SUMS
node scripts/warc-bundle.mjs . ../ye-warcs-release-assets
```

The validator checks archive completeness, gzip normalization, WARC and payload
digests, deterministic record identifiers, URL/filename agreement, prohibited
metadata, manifest consistency, and every published checksum.

## Using an archive

The files are standard gzip-compressed WARC 1.0 response records and can be read
with common WARC tooling. Because acquisition times are intentionally absent,
time-based replay indexes will display the documented sentinel date. Consult
`archives/manifest.csv` to locate an archive by domain or target URL.

## Important limitations

- This is a one-response-per-homepage collection, not a recursive crawl.
- Redirect destinations are recorded in the response headers, but redirect
  chains were not followed within these files.
- Capture-time evidence was intentionally removed and cannot be reconstructed
  from the public package.
- Public pages can contain third-party text, code, identifiers, and links. Their
  inclusion documents what the server returned and does not endorse them.
- Preserved payloads, target URLs, server content dates, and response evidence
  can be correlated by someone who already possesses another copy. Removing
  collection metadata cannot recall third-party downloads or caches, and the
  project does not claim otherwise.
- Archived content remains subject to the rights and lawful restrictions that
  apply to the original material. The project grants no new rights in it.

The surrounding `ye-domains` repository contains the historical domain corpus
and current DNS observations.
