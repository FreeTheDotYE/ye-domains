#!/usr/bin/env python3
"""Validate the privacy-minimized public .ye dataset without network access."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
PUBLIC_SUFFIXES = ("com.ye", "edu.ye", "gov.ye", "mil.ye", "net.ye", "org.ye", "ye")
DOMAIN_FIELDS = ["domain", "unicode_domain", "public_suffix", "registration_level"]
HOSTNAME_FIELDS = ["hostname", "unicode_hostname", "registrable_domain"]
REGISTRATION_KEYS = {
    "schema_version", "domain", "registry_ids_observed", "statuses_observed",
    "nameservers_observed", "delegation_signed_observed", "zone_signed_observed",
    "registration_dates_observed", "expiration_dates_observed",
    "last_changed_dates_observed",
}
SUMMARY_KEYS = {
    "schema_version", "registrable_domains", "hostnames",
    "domains_with_clean_registration_data", "domains_without_clean_registration_data",
    "public_suffix_counts", "privacy",
}
REGISTRY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,200}$")
STATUS_RE = re.compile(r"^[a-z0-9_]{1,80}$")
DATE_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
EVENT_ID_RE = re.compile(r"^[0-9a-f]{20}$")
DNS_FIELDS = {
    "a", "aaaa", "cname", "ns", "mx", "soa_mname", "soa_serial", "ds", "dnskey",
}
DNS_KEYS = DNS_FIELDS | {"status"}
DNS_STATUSES = {"records_present", "no_records", "nxdomain", "unobserved"}
MONITOR_STATE_KEYS = {"schema_version", "hostname", "registrable_domain", "dns"}
MONITOR_SUMMARY_KEYS = {
    "schema_version", "date", "hostnames_checked", "definitive", "inconclusive",
    "pending_hostnames", "confirmed_changes", "new_dns_discoveries", "status_counts",
}
MONITOR_EVENT_KEYS = {
    "schema_version", "date", "hostname", "field", "before", "after",
    "classification", "event_id",
}
SOHOBCOM_KEYS = {
    "schema_version", "as_of_date", "sohobcom_zone_records",
    "authoritative_mail_targets", "related_dns_records", "apex_addresses",
    "technical_overlaps", "interpretation",
}
SOHOBCOM_ROOT = "sohobcom.ye"
SOHOBCOM_INTERPRETATION = (
    "DNS target or address overlap is a technical research indicator only; "
    "it does not establish ownership, affiliation, intent, or wrongdoing."
)
FORBIDDEN_ARTIFACTS = {
    "data/observations.csv", "data/source_inventory.csv", "data/rejects.csv",
    "docs/methodology.md", "docs/archiving.md",
}
FORBIDDEN_PARTS = {"snapshots", "reports", "archives", "raw", "warc"}


def normalize_hostname(value: object) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    if not text or any(character.isspace() for character in text):
        return ""
    try:
        text = text.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(text) > 253:
        return ""
    labels = text.split(".")
    if any(
        not label or len(label) > 63
        or label.startswith("-") or label.endswith("-")
        or not re.fullmatch(r"[a-z0-9-]+", label)
        for label in labels
    ):
        return ""
    return text


def unicode_hostname(value: str) -> str:
    try:
        return ".".join(label.encode("ascii").decode("idna") for label in value.split("."))
    except UnicodeError:
        return value


def public_suffix(domain: str) -> str:
    matches = [
        suffix for suffix in PUBLIC_SUFFIXES
        if domain.endswith(f".{suffix}") and domain != suffix
    ]
    return max(matches, key=lambda value: value.count("."), default="")


def registrable_domain(hostname: str) -> str:
    suffix = public_suffix(hostname)
    if not suffix:
        return ""
    labels = hostname.split(".")
    suffix_labels = suffix.split(".")
    if len(labels) <= len(suffix_labels):
        return ""
    return ".".join(labels[-len(suffix_labels) - 1:])


def read_csv(path: Path, expected_fields: list[str]) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != expected_fields:
            raise ValueError(f"unexpected columns in {path}: {reader.fieldnames}")
        return list(reader)


def sorted_unique_strings(value: object, label: str, pattern: re.Pattern[str] | None = None) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"expected string array at {label}")
    if value != sorted(set(value)):
        raise ValueError(f"array is not sorted and unique at {label}")
    if pattern and not all(pattern.fullmatch(item) for item in value):
        raise ValueError(f"invalid string value at {label}")
    return value


def validate_files() -> None:
    for relative in FORBIDDEN_ARTIFACTS:
        if (ROOT / relative).exists():
            raise ValueError(f"provenance-bearing artifact must not be public: {relative}")
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts:
            continue
        lower_parts = {part.lower() for part in relative.parts}
        if "__pycache__" in lower_parts:
            raise ValueError(f"Python cache path is not allowed: {relative}")
        if path.name.lower().endswith((".orig", ".rej")):
            raise ValueError(f"patch byproduct is not allowed: {relative}")
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed: {path}")
        if not path.is_file():
            continue
        if lower_parts & FORBIDDEN_PARTS:
            raise ValueError(f"raw/report/archive path must not be public: {relative}")
        if re.search(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}", relative.as_posix()):
            raise ValueError(f"dated acquisition-style path is not allowed: {relative}")


def validate_domains() -> tuple[list[dict], set[str]]:
    rows = read_csv(ROOT / "data/domains.csv", DOMAIN_FIELDS)
    names = [row["domain"] for row in rows]
    if names != sorted(set(names)):
        raise ValueError("domains must be uniquely sorted")
    for row in rows:
        domain = normalize_hostname(row["domain"])
        suffix = public_suffix(domain)
        if not domain or registrable_domain(domain) != domain or domain != row["domain"]:
            raise ValueError(f"invalid registrable domain: {row['domain']}")
        if row["unicode_domain"] != unicode_hostname(domain):
            raise ValueError(f"invalid Unicode domain form: {domain}")
        if row["public_suffix"] != suffix:
            raise ValueError(f"invalid public suffix: {domain}")
        expected_level = "direct_under_ye" if suffix == "ye" else "under_structured_suffix"
        if row["registration_level"] != expected_level:
            raise ValueError(f"invalid registration level: {domain}")
    return rows, set(names)


def validate_hostnames(domains: set[str]) -> tuple[list[dict], set[str]]:
    rows = read_csv(ROOT / "data/hostnames.csv", HOSTNAME_FIELDS)
    names = [row["hostname"] for row in rows]
    if names != sorted(set(names)):
        raise ValueError("hostnames must be uniquely sorted")
    for row in rows:
        hostname = normalize_hostname(row["hostname"])
        domain = registrable_domain(hostname)
        if not hostname or hostname != row["hostname"] or domain != row["registrable_domain"]:
            raise ValueError(f"invalid hostname/domain mapping: {row['hostname']}")
        if domain not in domains:
            raise ValueError(f"hostname references an unknown domain: {hostname}")
        if row["unicode_hostname"] != unicode_hostname(hostname):
            raise ValueError(f"invalid Unicode hostname form: {hostname}")
    missing_roots = domains - set(names)
    if missing_roots:
        raise ValueError(f"registrable roots missing from hostname inventory: {len(missing_roots)}")
    return rows, set(names)


def validate_registration(domains: set[str]) -> list[dict]:
    rows = []
    path = ROOT / "data/registration.jsonl"
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or set(row) != REGISTRATION_KEYS:
                raise ValueError(f"unexpected registration schema at line {line_number}")
            if row["schema_version"] != SCHEMA_VERSION or row["domain"] not in domains:
                raise ValueError(f"invalid registration identity at line {line_number}")
            sorted_unique_strings(row["registry_ids_observed"], f"line {line_number}.registry_ids", REGISTRY_ID_RE)
            sorted_unique_strings(row["statuses_observed"], f"line {line_number}.statuses", STATUS_RE)
            nameservers = sorted_unique_strings(row["nameservers_observed"], f"line {line_number}.nameservers")
            if not all(normalize_hostname(value) == value for value in nameservers):
                raise ValueError(f"invalid nameserver at line {line_number}")
            for field in ("delegation_signed_observed", "zone_signed_observed"):
                values = row[field]
                if not isinstance(values, list) or values != sorted(set(values)):
                    raise ValueError(f"invalid Boolean history at line {line_number}.{field}")
                if not all(isinstance(value, bool) for value in values):
                    raise ValueError(f"non-Boolean history at line {line_number}.{field}")
            for field in (
                "registration_dates_observed", "expiration_dates_observed",
                "last_changed_dates_observed",
            ):
                values = sorted_unique_strings(row[field], f"line {line_number}.{field}", DATE_RE)
                for value in values:
                    datetime.strptime(value, "%Y-%m-%d")
            if not any(row[field] for field in row if field.endswith("_observed")):
                raise ValueError(f"registration row has no retained signal at line {line_number}")
            serialized = json.dumps(row, ensure_ascii=False).lower()
            if (
                "@" in serialized or "http://" in serialized or "https://" in serialized
                or re.search(r"t[0-9]{2}:[0-9]{2}:[0-9]{2}", serialized)
            ):
                raise ValueError(f"contact, URL, or precise timestamp leaked at line {line_number}")
            rows.append(row)
    names = [row["domain"] for row in rows]
    if names != sorted(set(names)):
        raise ValueError("registration rows must be uniquely sorted")
    return rows


def validate_analysis(domain_rows: list[dict]) -> None:
    rows = read_csv(
        ROOT / "analysis/public_suffix_distribution.csv",
        ["public_suffix", "domains", "share"],
    )
    counts = Counter(row["public_suffix"] for row in domain_rows)
    expected_suffixes = sorted(counts)
    if [row["public_suffix"] for row in rows] != expected_suffixes:
        raise ValueError("public suffix analysis has unexpected rows")
    for row in rows:
        suffix = row["public_suffix"]
        count = int(row["domains"])
        if count != counts[suffix]:
            raise ValueError(f"public suffix count mismatch: {suffix}")
        expected_share = f"{count / len(domain_rows):.6f}"
        if row["share"] != expected_share:
            raise ValueError(f"public suffix share mismatch: {suffix}")


def validate_summary(domain_rows: list[dict], hostname_rows: list[dict], registration_rows: list[dict]) -> dict:
    value = json.loads((ROOT / "data/summary.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != SUMMARY_KEYS:
        raise ValueError("unexpected summary schema")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected summary version")
    if value["registrable_domains"] != len(domain_rows):
        raise ValueError("summary domain count mismatch")
    if value["hostnames"] != len(hostname_rows):
        raise ValueError("summary hostname count mismatch")
    if value["domains_with_clean_registration_data"] != len(registration_rows):
        raise ValueError("summary registration count mismatch")
    if value["domains_without_clean_registration_data"] != len(domain_rows) - len(registration_rows):
        raise ValueError("summary missing-registration count mismatch")
    counts = dict(sorted(Counter(row["public_suffix"] for row in domain_rows).items()))
    if value["public_suffix_counts"] != counts:
        raise ValueError("summary suffix counts mismatch")
    if value["privacy"] != {
        "personal_contact_fields_published": False,
        "source_urls_published": False,
        "acquisition_timestamps_published": False,
    }:
        raise ValueError("summary privacy flags are invalid")
    return value


def canonical_date(value: object, label: str) -> str:
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        raise ValueError(f"invalid day-precision date at {label}")
    datetime.strptime(value, "%Y-%m-%d")
    return value


def dns_field(field: str, value: object, label: str) -> None:
    if value is None:
        raise ValueError(f"null DNS value at {label}")
    if field == "status":
        if value not in DNS_STATUSES:
            raise ValueError(f"invalid DNS status at {label}")
        return
    if field == "soa_serial":
        if (
            not isinstance(value, str)
            or (value and (not value.isdigit() or str(int(value)) != value))
        ):
            raise ValueError(f"invalid SOA serial at {label}")
        return
    values = sorted_unique_strings(value, label)
    if field in {"a", "aaaa"}:
        expected_version = 4 if field == "a" else 6
        for item in values:
            address = ipaddress.ip_address(item)
            if address.version != expected_version or str(address) != item:
                raise ValueError(f"invalid address at {label}")
    elif field in {"cname", "ns", "soa_mname"}:
        if not all(item and normalize_hostname(item) == item for item in values):
            raise ValueError(f"invalid DNS hostname at {label}")
    elif field == "mx":
        for item in values:
            match = re.fullmatch(r"([0-9]{1,5}) ([^\s]+)", item)
            if (
                not match or int(match.group(1)) > 65535
                or match.group(1) != str(int(match.group(1)))
                or not match.group(2) or normalize_hostname(match.group(2)) != match.group(2)
            ):
                raise ValueError(f"invalid MX value at {label}")
    elif field == "ds":
        for item in values:
            match = re.fullmatch(r"([0-9]{1,5}) ([0-9]{1,3}) ([0-9]{1,3}) ([0-9a-f]{2,128})", item)
            if (
                not match or int(match.group(1)) > 65535
                or int(match.group(2)) > 255 or int(match.group(3)) > 255
                or any(match.group(index) != str(int(match.group(index))) for index in range(1, 4))
                or len(match.group(4)) % 2
            ):
                raise ValueError(f"invalid DS value at {label}")
    elif field == "dnskey":
        for item in values:
            match = re.fullmatch(r"([0-9]{1,5}) ([0-9]{1,3}) ([0-9]{1,3}) ([0-9a-f]{64})", item)
            if (
                not match or int(match.group(1)) > 65535
                or int(match.group(2)) > 255 or int(match.group(3)) > 255
                or any(match.group(index) != str(int(match.group(index))) for index in range(1, 4))
            ):
                raise ValueError(f"invalid DNSKEY value at {label}")
    else:
        raise ValueError(f"unexpected DNS field at {label}")


def dns_state(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != DNS_KEYS:
        raise ValueError(f"unexpected DNS schema at {label}")
    for field, child in value.items():
        dns_field(field, child, f"{label}.{field}")
    has_rr_values = any(bool(value[field]) for field in DNS_FIELDS)
    if (value["status"] == "records_present") != has_rr_values:
        raise ValueError(
            f"DNS status and record values are inconsistent at {label}"
        )


def validate_monitor_manifest(monitoring: Path) -> None:
    manifest = json.loads((monitoring / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "files"}:
        raise ValueError("unexpected monitoring manifest schema")
    if manifest["schema_version"] != SCHEMA_VERSION or not isinstance(manifest["files"], dict):
        raise ValueError("invalid monitoring manifest")
    actual = {}
    allowed = {
        "state.jsonl",
        "discovered-hostnames.csv",
        "latest.json",
        "sohobcom-dns.json",
    }
    for path in sorted(monitoring.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"monitoring symlink is not allowed: {path}")
        if path.is_file() and path.name != "manifest.json":
            relative = path.relative_to(monitoring).as_posix()
            if relative not in allowed and not re.fullmatch(
                r"events/[0-9]{4}/(0[1-9]|1[0-2])\.jsonl", relative
            ):
                raise ValueError(f"unexpected monitoring output: {relative}")
            actual[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    if manifest["files"] != actual or not actual:
        raise ValueError("monitoring manifest does not match files")


def dns_targets(state: dict) -> set[str]:
    targets = (
        set(state.get("cname", []))
        | set(state.get("ns", []))
        | set(state.get("soa_mname", []))
    )
    for value in state.get("mx", []):
        parts = value.split(" ", 1)
        if len(parts) == 2:
            targets.add(parts[1])
    return targets


def expected_sohobcom_view(state_rows: list[dict], as_of_date: str) -> dict:
    state_map = {row["hostname"]: row["dns"] for row in state_rows}
    zone_rows = [
        row for row in state_rows
        if row["hostname"] == SOHOBCOM_ROOT
        or row["hostname"].endswith(f".{SOHOBCOM_ROOT}")
    ]
    apex_dns = state_map.get(SOHOBCOM_ROOT, {})
    authoritative_mail_targets = (
        set(apex_dns.get("ns", []))
        | set(apex_dns.get("soa_mname", []))
    )
    for value in apex_dns.get("mx", []):
        parts = value.split(" ", 1)
        if len(parts) == 2:
            authoritative_mail_targets.add(parts[1])
    apex_addresses = set(apex_dns.get("a", [])) | set(apex_dns.get("aaaa", []))

    overlaps: dict[str, dict[str, set[str]]] = {}
    for row in state_rows:
        domain = row["registrable_domain"]
        if domain == SOHOBCOM_ROOT:
            continue
        targets = dns_targets(row["dns"])
        authority_matches = targets & authoritative_mail_targets
        sohobcom_matches = {
            target for target in targets
            if target == SOHOBCOM_ROOT or target.endswith(f".{SOHOBCOM_ROOT}")
        }
        address_matches = (
            set(row["dns"].get("a", [])) | set(row["dns"].get("aaaa", []))
        ) & apex_addresses
        if not authority_matches and not sohobcom_matches and not address_matches:
            continue
        entry = overlaps.setdefault(
            domain,
            {
                "authority_or_mail_targets": set(),
                "sohobcom_target_hosts": set(),
                "shared_apex_addresses": set(),
            },
        )
        entry["authority_or_mail_targets"].update(authority_matches)
        entry["sohobcom_target_hosts"].update(sohobcom_matches)
        entry["shared_apex_addresses"].update(address_matches)

    return {
        "schema_version": SCHEMA_VERSION,
        "as_of_date": as_of_date,
        "sohobcom_zone_records": [
            {"hostname": row["hostname"], "dns": row["dns"]}
            for row in sorted(zone_rows, key=lambda item: item["hostname"])
        ],
        "authoritative_mail_targets": sorted(authoritative_mail_targets),
        "related_dns_records": [
            {"hostname": row["hostname"], "dns": row["dns"]}
            for row in state_rows
            if row["hostname"] in authoritative_mail_targets
        ],
        "apex_addresses": sorted(apex_addresses),
        "technical_overlaps": [
            {
                "domain": domain,
                "authority_or_mail_targets": sorted(values["authority_or_mail_targets"]),
                "sohobcom_target_hosts": sorted(values["sohobcom_target_hosts"]),
                "shared_apex_addresses": sorted(values["shared_apex_addresses"]),
            }
            for domain, values in sorted(overlaps.items())
        ],
        "interpretation": SOHOBCOM_INTERPRETATION,
    }


def validate_monitoring() -> dict:
    monitoring = ROOT / "monitoring"
    if not monitoring.is_dir():
        raise ValueError("monitoring output is missing")
    validate_monitor_manifest(monitoring)

    state_rows = []
    with (monitoring / "state.jsonl").open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            row = json.loads(line)
            if not isinstance(row, dict) or set(row) != MONITOR_STATE_KEYS:
                raise ValueError(f"unexpected monitor state schema at line {line_number}")
            if row["schema_version"] != SCHEMA_VERSION:
                raise ValueError(f"invalid monitor state version at line {line_number}")
            hostname = row["hostname"]
            domain = row["registrable_domain"]
            if (
                normalize_hostname(hostname) != hostname or not hostname.endswith(".ye")
                or normalize_hostname(domain) != domain or not domain.endswith(".ye")
                or not (hostname == domain or hostname.endswith(f".{domain}"))
            ):
                raise ValueError(f"invalid monitor hostname mapping at line {line_number}")
            dns_state(row["dns"], f"monitor state line {line_number}")
            state_rows.append(row)
    state_names = [row["hostname"] for row in state_rows]
    if state_names != sorted(set(state_names)):
        raise ValueError("monitor state must be uniquely sorted")

    discovered = read_csv(
        monitoring / "discovered-hostnames.csv",
        ["hostname", "registrable_domain"],
    )
    discovered_names = [row["hostname"] for row in discovered]
    if discovered_names != sorted(set(discovered_names)):
        raise ValueError("discovered hostnames must be uniquely sorted")
    for row in discovered:
        hostname, domain = row["hostname"], row["registrable_domain"]
        if (
            normalize_hostname(hostname) != hostname or not hostname.endswith(".ye")
            or normalize_hostname(domain) != domain or not domain.endswith(".ye")
            or not (hostname == domain or hostname.endswith(f".{domain}"))
        ):
            raise ValueError(f"invalid discovered hostname mapping: {hostname}")

    latest = json.loads((monitoring / "latest.json").read_text(encoding="utf-8"))
    if not isinstance(latest, dict) or set(latest) != MONITOR_SUMMARY_KEYS:
        raise ValueError("unexpected monitoring summary schema")
    if latest["schema_version"] != SCHEMA_VERSION:
        raise ValueError("invalid monitoring summary version")
    canonical_date(latest["date"], "monitoring latest")
    for field in (
        "hostnames_checked", "definitive", "inconclusive", "pending_hostnames",
        "confirmed_changes", "new_dns_discoveries",
    ):
        if not isinstance(latest[field], int) or isinstance(latest[field], bool) or latest[field] < 0:
            raise ValueError(f"invalid monitoring count: {field}")
    if (
        latest["hostnames_checked"] != len(state_rows)
        or latest["definitive"] + latest["inconclusive"] != len(state_rows)
        or latest["pending_hostnames"] > len(state_rows)
    ):
        raise ValueError("monitoring summary counts do not reconcile")
    actual_statuses = dict(sorted(Counter(row["dns"]["status"] for row in state_rows).items()))
    if latest["status_counts"] != actual_statuses:
        raise ValueError("monitoring status counts do not reconcile")

    view = json.loads((monitoring / "sohobcom-dns.json").read_text(encoding="utf-8"))
    if not isinstance(view, dict) or set(view) != SOHOBCOM_KEYS:
        raise ValueError("unexpected Sohobcom DNS view schema")
    expected_view = expected_sohobcom_view(state_rows, latest["date"])
    if view != expected_view:
        raise ValueError("Sohobcom DNS view is not the exact state-derived projection")
    zone_count = len(view["sohobcom_zone_records"])
    overlap_count = len(view["technical_overlaps"])

    event_count = 0
    event_ids: set[str] = set()
    for path in sorted((monitoring / "events").glob("*/*.jsonl")) if (monitoring / "events").exists() else []:
        rows = []
        with path.open(encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, 1):
                row = json.loads(line)
                if not isinstance(row, dict) or set(row) != MONITOR_EVENT_KEYS:
                    raise ValueError(f"unexpected event schema at {path}:{line_number}")
                if row["schema_version"] != SCHEMA_VERSION:
                    raise ValueError(f"invalid event version at {path}:{line_number}")
                canonical_date(row["date"], f"{path}:{line_number}")
                if normalize_hostname(row["hostname"]) != row["hostname"]:
                    raise ValueError(f"invalid event hostname at {path}:{line_number}")
                if row["field"] not in DNS_KEYS:
                    raise ValueError(f"invalid event field at {path}:{line_number}")
                dns_field(row["field"], row["before"], f"{path}:{line_number}.before")
                dns_field(row["field"], row["after"], f"{path}:{line_number}.after")
                if row["classification"] not in {"review", "telemetry", "informational"}:
                    raise ValueError(f"invalid event classification at {path}:{line_number}")
                if not EVENT_ID_RE.fullmatch(str(row["event_id"])):
                    raise ValueError(f"invalid event id at {path}:{line_number}")
                public_payload = dict(row)
                event_id = public_payload.pop("event_id")
                expected_id = hashlib.sha256(
                    json.dumps(
                        public_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ).hexdigest()[:20]
                if event_id != expected_id or event_id in event_ids:
                    raise ValueError(f"non-public or duplicate event id at {path}:{line_number}")
                event_ids.add(event_id)
                rows.append(row)
                event_count += 1
        ordering = [(row["date"], row["hostname"], row["field"], row["event_id"]) for row in rows]
        if ordering != sorted(ordering):
            raise ValueError(f"events are not sorted: {path}")

    for path in monitoring.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8").lower()
        if re.search(r"t[0-9]{2}:[0-9]{2}:[0-9]{2}", text):
            raise ValueError(f"precise run time leaked into public monitoring: {path}")
        for forbidden in (
            '"observed_at"', '"evidence"', '"parent"', '"record_type"',
            '"url"', "rname", "pricing", "price_signal",
        ):
            if forbidden in text:
                raise ValueError(f"private collection detail leaked into public monitoring: {path}")
    return {
        "monitor_state_hostnames": len(state_rows),
        "monitor_discovered_hostnames": len(discovered),
        "monitor_events": event_count,
        "monitor_date": latest["date"],
        "sohobcom_zone_hostnames": zone_count,
        "sohobcom_overlap_domains": overlap_count,
    }


def main() -> int:
    validate_files()
    domain_rows, domains = validate_domains()
    hostname_rows, _ = validate_hostnames(domains)
    registration_rows = validate_registration(domains)
    validate_analysis(domain_rows)
    summary = validate_summary(domain_rows, hostname_rows, registration_rows)
    monitor_summary = validate_monitoring()
    print(json.dumps({"ok": True, **summary, **monitor_summary}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
