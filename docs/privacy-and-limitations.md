# Privacy, safety, and limitations

Precise historical source identities, acquisition order, and collection timestamps are not published because they could expose collectors. The repository states this limitation explicitly instead of presenting the corpus as independently reproducible.

The registration export excludes all registrant, administrative, technical, billing, and abuse-contact data. It also excludes entity cards, email addresses, phone numbers, postal addresses, source links, raw registration-source response bodies, and database-refresh timestamps. Duplicate technical values are collapsed without retaining source-to-value mappings.

The domain list is historical. A listed name may be unregistered, expired, undelegated, parked, unreachable, or reassigned. A registration status or lifecycle date may also be stale. Current status must be checked against the automated DNS state and, where stakes are high, independently verified.

Structured registry-level recognition is a technical boundary used to map hostnames to the longest registrable root. Recognized levels include `biz.ye`, `com.ye`, `edu.ye`, `gov.ye`, `hospital.ye`, `law.ye`, `me.ye`, `mil.ye`, `net.ye`, `org.ye`, `pro.ye`, `school.ye`, `tv.ye`, and `uni.ye`. The corpus currently has no observed child registrations beneath `biz.ye`, `me.ye`, `pro.ye`, or `tv.ye`. Sharing a registry level does not establish ownership, affiliation, or another relationship.

Registration status arrays retain explicit safe-record values and do not add a second status solely because it is semantically related.

## Public webpage archives

The 219 published WARC files are a separate collection of public homepage responses. Each contains one root-URL response, not a recursive crawl. Response payload bytes are preserved because they are the archival evidence; they are not registration-source responses and are not covered by the contact-field removal applied to `data/registration.jsonl`.

Collection-bound WARC and HTTP metadata is removed or normalized. This includes exact capture timestamps, cookies, per-request and tracing identifiers, client/proxy forwarding fields, rate-limit state, hop-by-hop transport fields, and tool-added archive headers. Every public record uses the fixed `WARC-Date` value `1970-01-01T00:00:00Z` as a privacy sentinel. It must not be interpreted as an acquisition date.

Stable server-provided content metadata such as `Last-Modified` can remain. Response bodies can also contain public dates, analytics identifiers, contact details, or other information placed online by the originating site. Removing these values would alter the archived evidence. Researchers must therefore review archived content in context and avoid using it to target individuals.

Payload hashes, target URLs, retained server metadata, and byte-identical content can be correlated by someone who already possesses another copy. Normalization cannot recall third-party downloads, mirrors, caches, or earlier copies. Pre-normalization records remain restricted and are not part of the public repository.

An archive record describes a historical response only. It does not prove that a site is currently reachable, registered, controlled by the same party, or accurately represented by its content. Inclusion does not establish ownership, affiliation, political alignment, intent, or wrongdoing. Third-party archived content is not placed under CC0; see [`archives/RIGHTS.md`](../archives/RIGHTS.md).

DNS records, shared addresses, nameservers, mail exchangers, authority servers, and certificate or hosting relationships are technical indicators only. They do not establish legal ownership, beneficial control, political affiliation, intent, or wrongdoing.

The monitor is limited to DNS observation and does not conduct active network or application-security testing. Its public outputs are reduced to the normalized state, confirmed changes, and day-level run information needed for research.
