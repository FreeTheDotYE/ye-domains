#!/usr/bin/env python3
"""Strict validation for the public technical-evidence tree."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import ssl
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from validate_dataset import (
    DATE_RE,
    SCHEMA_VERSION,
    normalize_hostname,
    registrable_domain,
)


HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest_object(value: object) -> str:
    return digest_bytes(
        canonical_json(value).encode("utf-8")
    )


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(
                    f"non-object JSON at {path}:{line_number}"
                )
            rows.append(value)
    return rows


FIXED_FILES = {
    "README.md",
    "common-crawl/captures.jsonl",
    "common-crawl/collections.jsonl",
    "common-crawl/domains.jsonl",
    "common-crawl/hostnames.jsonl",
    "infrastructure/edges.jsonl",
    "infrastructure/nodes.jsonl",
    "infrastructure/summary.json",
    "tls/current.jsonl",
    "tls/observations.jsonl",
}
CERTIFICATE_PATH_RE = re.compile(
    r"^tls/certificates/sha256/([0-9a-f]{2})/"
    r"([0-9a-f]{64})\.pem$"
)
COLLECTION_RE = re.compile(
    r"^CC-MAIN-[0-9]{4}-[0-9]{2}$"
)
STRUCTURED_SUFFIX_COUNT = 14
HOST_SUMMARY_KEYS = {
    "schema_version",
    "hostname",
    "registrable_domain",
    "first_capture_date",
    "last_capture_date",
    "first_capture_id",
    "last_capture_id",
    "capture_count",
    "collection_count",
}
DOMAIN_SUMMARY_KEYS = (
    HOST_SUMMARY_KEYS
    - {"hostname", "registrable_domain"}
    | {"domain", "hostname_count"}
)
COLLECTION_KEYS = {
    "schema_version",
    "collection",
    "complete",
    "completed_suffixes",
    "total_suffixes",
}
CERTIFICATE_KEYS = {
    "serial_number",
    "subject",
    "issuer",
    "not_before_date",
    "not_after_date",
    "dns_names",
}
TLS_OBSERVATION_KEYS = {
    "schema_version",
    "observed_date",
    "hostname",
    "ip_address",
    "tls_version",
    "cipher",
    "alpn",
    "certificate_sha256",
    "certificate",
    "classification",
    "observation_id",
}
TLS_CURRENT_KEYS = {
    "schema_version",
    "hostname",
    "ip_address",
    "tls_version",
    "cipher",
    "alpn",
    "certificate_sha256",
    "certificate",
    "first_seen_date",
    "last_seen_date",
    "last_checked_date",
}
NODE_KINDS = {
    "domain",
    "hostname",
    "ip_address",
    "network_prefix",
    "asn",
    "registrar",
    "tls_certificate",
    "dataset",
}
RELATION_KINDS = {
    "contains_hostname": ("domain", "hostname"),
    "resolves_to": ("hostname", "ip_address"),
    "cname_to": ("hostname", "hostname"),
    "delegated_to": ("domain", "hostname"),
    "soa_authority": ("domain", "hostname"),
    "mail_routed_to": ("domain", "hostname"),
    "registered_via": ("domain", "registrar"),
    "observed_in_web_archive": ("hostname", "dataset"),
    "presents_certificate": ("hostname", "tls_certificate"),
    "covered_by_prefix": ("ip_address", "network_prefix"),
    "originated_by": ("network_prefix", "asn"),
}
RELATION_SOURCES = {
    "contains_hostname": {"dns", "common_crawl"},
    "resolves_to": {"dns"},
    "cname_to": {"dns"},
    "delegated_to": {"dns"},
    "soa_authority": {"dns"},
    "mail_routed_to": {"dns"},
    "registered_via": {"rdap", "whois", "registration"},
    "observed_in_web_archive": {"common_crawl"},
    "presents_certificate": {"tls"},
    "covered_by_prefix": {"ripe_ris"},
    "originated_by": {"ripe_ris"},
}
GRAPH_EDGE_KEYS = {
    "schema_version",
    "edge_id",
    "source",
    "relation",
    "target",
    "first_seen_date",
    "last_seen_date",
    "active",
    "observation_sources",
}


def valid_date(value: object) -> bool:
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def canonical_rows(path: Path) -> list[dict]:
    rows = load_jsonl(path)
    expected = "".join(
        canonical_json(row) + "\n"
        for row in rows
    ).encode("utf-8")
    if path.read_bytes() != expected:
        raise ValueError(
            f"non-canonical JSONL: {path}"
        )
    return rows


def validate_manifest(root: Path) -> None:
    path = root / "MANIFEST.sha256"
    lines = path.read_text(encoding="ascii").splitlines()
    declared = {}
    for line in lines:
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([^\s].*)",
            line,
        )
        if not match or match.group(2) in declared:
            raise ValueError("invalid evidence manifest")
        declared[match.group(2)] = match.group(1)
    actual = {}
    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            raise ValueError(
                f"symlink is not allowed: {item}"
            )
        if (
            item.is_file()
            and item.name != "MANIFEST.sha256"
        ):
            relative = item.relative_to(root).as_posix()
            if (
                relative not in FIXED_FILES
                and not CERTIFICATE_PATH_RE.fullmatch(
                    relative
                )
            ):
                raise ValueError(
                    f"unexpected evidence file: {relative}"
                )
            actual[relative] = digest_bytes(
                item.read_bytes()
            )
    if declared != actual:
        raise ValueError(
            "evidence manifest does not match files"
        )


def validate_common_crawl(root: Path) -> dict:
    captures = canonical_rows(
        root / "common-crawl/captures.jsonl"
    )
    capture_ids = set()
    ordering = []
    for row in captures:
        required = {
            "schema_version",
            "collection",
            "capture_date",
            "hostname",
            "registrable_domain",
            "http_status",
            "mime",
            "content_digest",
            "warc_filename",
            "warc_offset",
            "warc_length",
            "url_sha256",
            "capture_id",
        }
        if (
            set(row) != required
            or row["schema_version"] != SCHEMA_VERSION
            or not COLLECTION_RE.fullmatch(
                str(row["collection"])
            )
            or not valid_date(row["capture_date"])
            or normalize_hostname(row["hostname"])
            != row["hostname"]
            or registrable_domain(row["hostname"])
            != row["registrable_domain"]
            or not HEX_RE.fullmatch(
                str(row["url_sha256"])
            )
            or not row["warc_filename"].startswith(
                "crawl-data/"
            )
            or not isinstance(
                row["warc_offset"],
                int,
            )
            or row["warc_offset"] < 0
            or not isinstance(
                row["warc_length"],
                int,
            )
            or row["warc_length"] <= 0
        ):
            raise ValueError(
                "invalid Common Crawl capture"
            )
        payload = dict(row)
        capture_id = payload.pop("capture_id")
        if (
            capture_id != digest_object(payload)
            or capture_id in capture_ids
        ):
            raise ValueError(
                "invalid or duplicate capture id"
            )
        capture_ids.add(capture_id)
        ordering.append(
            (
                row["capture_date"],
                row["hostname"],
                capture_id,
            )
        )
    if ordering != sorted(ordering):
        raise ValueError(
            "Common Crawl captures are not sorted"
        )

    hostnames = canonical_rows(
        root / "common-crawl/hostnames.jsonl"
    )
    domains = canonical_rows(
        root / "common-crawl/domains.jsonl"
    )

    def summary(rows: list[dict], identity: dict) -> dict:
        ordered = sorted(
            rows,
            key=lambda row: (
                row["capture_date"],
                row["capture_id"],
            ),
        )
        return {
            "schema_version": SCHEMA_VERSION,
            **identity,
            "first_capture_date": ordered[0]["capture_date"],
            "last_capture_date": ordered[-1]["capture_date"],
            "first_capture_id": ordered[0]["capture_id"],
            "last_capture_id": ordered[-1]["capture_id"],
            "capture_count": len(ordered),
            "collection_count": len(
                {row["collection"] for row in ordered}
            ),
        }

    by_host: dict[str, list[dict]] = {}
    by_domain: dict[str, list[dict]] = {}
    for row in captures:
        by_host.setdefault(row["hostname"], []).append(row)
        by_domain.setdefault(
            row["registrable_domain"],
            [],
        ).append(row)
    expected_hostnames = [
        summary(
            rows,
            {
                "hostname": hostname,
                "registrable_domain": rows[0][
                    "registrable_domain"
                ],
            },
        )
        for hostname, rows in sorted(by_host.items())
    ]
    expected_domains = []
    for domain, rows in sorted(by_domain.items()):
        value = summary(rows, {"domain": domain})
        value["hostname_count"] = len(
            {row["hostname"] for row in rows}
        )
        expected_domains.append(value)
    if (
        hostnames != expected_hostnames
        or any(set(row) != HOST_SUMMARY_KEYS for row in hostnames)
    ):
        raise ValueError(
            "Common Crawl hostname summaries mismatch captures"
        )
    if (
        domains != expected_domains
        or any(set(row) != DOMAIN_SUMMARY_KEYS for row in domains)
    ):
        raise ValueError(
            "Common Crawl domain summaries mismatch captures"
        )

    collections = canonical_rows(
        root / "common-crawl/collections.jsonl"
    )
    if [row.get("collection") for row in collections] != sorted(
        {row.get("collection") for row in collections}
    ):
        raise ValueError(
            "Common Crawl collections are not unique"
        )
    for row in collections:
        completed = row.get("completed_suffixes")
        total = row.get("total_suffixes")
        if (
            set(row) != COLLECTION_KEYS
            or row["schema_version"] != SCHEMA_VERSION
            or not COLLECTION_RE.fullmatch(
                str(row["collection"])
            )
            or not isinstance(row["complete"], bool)
            or type(completed) is not int
            or type(total) is not int
            or total != STRUCTURED_SUFFIX_COUNT
            or not 0 <= completed <= total
            or row["complete"] != (completed == total)
        ):
            raise ValueError(
                "invalid Common Crawl collection state"
            )
    return {
        "common_crawl_captures": len(captures),
        "common_crawl_hostnames": len(hostnames),
        "common_crawl_domains": len(domains),
        "common_crawl_collections": len(collections),
    }


def flatten_name(value: object) -> str:
    parts = []
    if isinstance(value, (list, tuple)):
        for rdn in value:
            if not isinstance(rdn, (list, tuple)):
                continue
            for item in rdn:
                if (
                    isinstance(item, (list, tuple))
                    and len(item) == 2
                ):
                    parts.append(f"{item[0]}={item[1]}")
    return "/".join(parts)[:2000]


def normalize_certificate_dns_name(value: object) -> str:
    text = str(value or "").strip().lower().rstrip(".")
    wildcard = text.startswith("*.")
    if wildcard:
        text = text[2:]
    hostname = normalize_hostname(text)
    if not hostname:
        return ""
    return f"*.{hostname}" if wildcard else hostname


def decoded_certificate(path: Path) -> dict:
    value = ssl._ssl._test_decode_cert(str(path))
    dns_names = sorted(
        {
            name
            for kind, raw in value.get("subjectAltName", [])
            if kind == "DNS"
            and (
                name := normalize_certificate_dns_name(raw)
            )
        }
    )

    def certificate_date(field: str) -> str:
        raw = value.get(field)
        if not raw:
            return ""
        timestamp = ssl.cert_time_to_seconds(raw)
        return datetime.fromtimestamp(
            timestamp,
            UTC,
        ).strftime("%Y-%m-%d")

    return {
        "serial_number": str(value.get("serialNumber", "")),
        "subject": flatten_name(value.get("subject")),
        "issuer": flatten_name(value.get("issuer")),
        "not_before_date": certificate_date("notBefore"),
        "not_after_date": certificate_date("notAfter"),
        "dns_names": dns_names,
    }


def certificate_paths(root: Path) -> dict[str, dict]:
    values = {}
    certificate_root = root / "tls/certificates"
    if not certificate_root.exists():
        return values
    for path in certificate_root.rglob("*.pem"):
        relative = path.relative_to(root).as_posix()
        match = CERTIFICATE_PATH_RE.fullmatch(relative)
        if not match or match.group(1) != match.group(2)[:2]:
            raise ValueError(
                f"invalid certificate path: {relative}"
            )
        pem = path.read_text(encoding="ascii")
        try:
            actual = hashlib.sha256(
                ssl.PEM_cert_to_DER_cert(pem)
            ).hexdigest()
            metadata = decoded_certificate(path)
        except (ValueError, ssl.SSLError) as exc:
            raise ValueError(
                f"invalid PEM certificate: {relative}"
            ) from exc
        if actual != match.group(2) or set(metadata) != CERTIFICATE_KEYS:
            raise ValueError(
                f"certificate digest or metadata mismatch: {relative}"
            )
        values[actual] = {
            "path": path,
            "certificate": metadata,
        }
    return values


def canonical_ip(value: object) -> bool:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return str(address) == value


def valid_tls_common(row: dict, certificates: dict[str, dict]) -> bool:
    certificate_sha = row.get("certificate_sha256")
    return (
        row.get("schema_version") == SCHEMA_VERSION
        and normalize_hostname(row.get("hostname"))
        == row.get("hostname")
        and canonical_ip(row.get("ip_address"))
        and certificate_sha in certificates
        and row.get("certificate")
        == certificates.get(certificate_sha, {}).get("certificate")
        and all(
            isinstance(row.get(field), str)
            and len(row[field]) <= 500
            for field in ("tls_version", "cipher", "alpn")
        )
    )


def validate_tls(root: Path) -> dict:
    certificates = certificate_paths(root)
    observations = canonical_rows(
        root / "tls/observations.jsonl"
    )
    observation_ids = set()
    ordering = []
    for row in observations:
        payload = dict(row)
        observation_id = payload.pop(
            "observation_id",
            "",
        )
        if (
            set(row) != TLS_OBSERVATION_KEYS
            or not valid_tls_common(row, certificates)
            or not valid_date(row.get("observed_date"))
            or row.get("classification")
            not in {
                "deployment_observed",
                "deployment_changed",
            }
            or observation_id != digest_object(payload)
            or observation_id in observation_ids
        ):
            raise ValueError(
                "invalid TLS observation"
            )
        observation_ids.add(observation_id)
        ordering.append(
            (
                row["observed_date"],
                row["hostname"],
                observation_id,
            )
        )
    if ordering != sorted(ordering):
        raise ValueError(
            "TLS observations are not sorted"
        )

    current = canonical_rows(
        root / "tls/current.jsonl"
    )
    if [row.get("hostname") for row in current] != sorted(
        {row.get("hostname") for row in current}
    ):
        raise ValueError(
            "TLS current rows are not unique"
        )
    for row in current:
        if (
            set(row) != TLS_CURRENT_KEYS
            or not valid_tls_common(row, certificates)
            or not all(
                valid_date(row.get(field))
                for field in (
                    "first_seen_date",
                    "last_seen_date",
                    "last_checked_date",
                )
            )
            or row["first_seen_date"] > row["last_seen_date"]
            or row["last_seen_date"] > row["last_checked_date"]
        ):
            raise ValueError(
                "invalid current TLS deployment"
            )
    referenced = {
        row["certificate_sha256"]
        for row in observations + current
    }
    if referenced != set(certificates):
        raise ValueError(
            "unreferenced or missing TLS certificate"
        )
    return {
        "tls_certificates": len(certificates),
        "tls_observations": len(observations),
        "tls_current": len(current),
    }

def valid_node_value(kind: str, value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if kind == "domain":
        return registrable_domain(value) == value
    if kind == "hostname":
        return normalize_hostname(value) == value
    if kind == "ip_address":
        return canonical_ip(value)
    if kind == "network_prefix":
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return str(network) == value
    if kind == "asn":
        return value.isdigit() and 0 <= int(value) <= 4_294_967_295
    if kind == "registrar":
        return len(value) <= 200 and not any(
            character.isspace() for character in value
        )
    if kind == "tls_certificate":
        return bool(HEX_RE.fullmatch(value))
    if kind == "dataset":
        return value == "common-crawl"
    return False


def validate_graph(root: Path) -> dict:
    nodes = canonical_rows(
        root / "infrastructure/nodes.jsonl"
    )
    node_ids = []
    kinds = {}
    for row in nodes:
        if (
            set(row)
            != {
                "schema_version",
                "node_id",
                "kind",
                "value",
            }
            or row["schema_version"] != SCHEMA_VERSION
            or row["kind"] not in NODE_KINDS
            or not valid_node_value(row["kind"], row["value"])
            or row["node_id"]
            != f"{row['kind']}:{row['value']}"
        ):
            raise ValueError(
                "invalid infrastructure node"
            )
        node_ids.append(row["node_id"])
        kinds[row["node_id"]] = row["kind"]
    if node_ids != sorted(set(node_ids)):
        raise ValueError(
            "infrastructure nodes are not unique"
        )
    node_set = set(node_ids)

    edges = canonical_rows(
        root / "infrastructure/edges.jsonl"
    )
    edge_ids = []
    for row in edges:
        relation = row.get("relation")
        sources = row.get("observation_sources")
        expected_kinds = RELATION_KINDS.get(relation)
        if (
            set(row) != GRAPH_EDGE_KEYS
            or row["schema_version"] != SCHEMA_VERSION
            or row["source"] not in node_set
            or row["target"] not in node_set
            or expected_kinds is None
            or (kinds[row["source"]], kinds[row["target"]])
            != expected_kinds
            or row["edge_id"]
            != digest_object(
                {
                    "source": row["source"],
                    "relation": relation,
                    "target": row["target"],
                }
            )
            or not isinstance(row["active"], bool)
            or not valid_date(row["first_seen_date"])
            or not valid_date(row["last_seen_date"])
            or row["first_seen_date"] > row["last_seen_date"]
            or not isinstance(sources, list)
            or not sources
            or sources != sorted(set(sources))
            or not set(sources).issubset(
                RELATION_SOURCES[relation]
            )
        ):
            raise ValueError(
                "invalid infrastructure edge"
            )
        edge_ids.append(row["edge_id"])
    if edge_ids != sorted(set(edge_ids)):
        raise ValueError(
            "infrastructure edges are not unique"
        )

    summary = json.loads(
        (
            root
            / "infrastructure/summary.json"
        ).read_text(encoding="utf-8")
    )
    expected = {
        "schema_version": SCHEMA_VERSION,
        "as_of_date": summary.get("as_of_date"),
        "nodes": len(nodes),
        "edges": len(edges),
        "active_edges": sum(
            bool(row["active"])
            for row in edges
        ),
        "node_kinds": dict(
            sorted(
                Counter(
                    row["kind"] for row in nodes
                ).items()
            )
        ),
        "relations": dict(
            sorted(
                Counter(
                    row["relation"] for row in edges
                ).items()
            )
        ),
    }
    if (
        not valid_date(summary.get("as_of_date"))
        or summary != expected
        or any(
            row["last_seen_date"] > summary["as_of_date"]
            for row in edges
        )
    ):
        raise ValueError(
            "infrastructure summary mismatch"
        )
    return {
        "graph_nodes": len(nodes),
        "graph_edges": len(edges),
        "graph_active_edges": expected[
            "active_edges"
        ],
    }


def validate_evidence(root: Path) -> dict:
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(
            "evidence directory is missing"
        )
    validate_manifest(root)
    result = {
        **validate_common_crawl(root),
        **validate_tls(root),
        **validate_graph(root),
    }
    for path in root.rglob("*.jsonl"):
        text = path.read_text(encoding="utf-8")
        if re.search(
            r"T[0-9]{2}:[0-9]{2}:[0-9]{2}",
            text,
        ):
            raise ValueError(
                f"precise run time leaked: {path}"
            )
    return {"tracking_ok": True, **result}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "root",
        type=Path,
    )
    args = parser.parse_args()
    print(
        canonical_json(
            validate_evidence(args.root)
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
