import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import {
  SENTINEL_DATE,
  WARC_HEADER_ORDER,
  assertPublicHomepageTarget,
  containsPrivateMetadata,
  headerValues,
  isRemovedHttpHeader,
  oneHeader,
  parseWarcRecord,
  sha256Hex,
  stableRecordId,
  verifyCoreDigests,
} from "./warc-lib.mjs";

const MANIFEST_FIELDS = [
  "schema_version", "domain", "target_url", "http_status", "media_type",
  "compressed_bytes", "uncompressed_bytes", "payload_bytes", "warc_sha256",
  "payload_sha256", "warc_record_id",
];
const DOMAIN_FIELDS = [
  "domain", "unicode_domain", "public_suffix", "registration_level",
];

function fail(message) { throw new Error(message); }

function parseCsv(text) {
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { field += '"'; i += 1; }
      else if (char === '"') quoted = false;
      else field += char;
    } else if (char === '"' && field === "") quoted = true;
    else if (char === ",") { row.push(field); field = ""; }
    else if (char === "\n") { row.push(field); rows.push(row); row = []; field = ""; }
    else if (char !== "\r") field += char;
  }
  if (quoted) fail("unterminated CSV quote");
  if (field || row.length) fail("CSV must end with LF");
  return rows;
}

function readManifest(root) {
  const rows = parseCsv(fs.readFileSync(path.join(root, "archives", "manifest.csv"), "utf8"));
  if (rows.length < 2) fail("empty manifest");
  if (JSON.stringify(rows[0]) !== JSON.stringify(MANIFEST_FIELDS)) fail("unexpected manifest schema");
  return rows.slice(1).map((values) => {
    if (values.length !== MANIFEST_FIELDS.length) fail("malformed manifest row");
    return Object.fromEntries(MANIFEST_FIELDS.map((field, index) => [field, values[index]]));
  });
}

function readCorpusDomains(root) {
  const relative = path.join("data", "domains.csv");
  const rows = parseCsv(fs.readFileSync(path.join(root, relative), "utf8"));
  if (rows.length < 2) fail("empty domain corpus");
  if (JSON.stringify(rows[0]) !== JSON.stringify(DOMAIN_FIELDS)) {
    fail("unexpected domain corpus schema");
  }
  const domains = new Set();
  for (const values of rows.slice(1)) {
    if (values.length !== DOMAIN_FIELDS.length) fail("malformed domain corpus row");
    const row = Object.fromEntries(
      DOMAIN_FIELDS.map((field, index) => [field, values[index]]),
    );
    if (domains.has(row.domain)) fail("duplicate corpus domain: " + row.domain);
    const domainLabels = row.domain.split(".");
    const suffixLabels = row.public_suffix.split(".");
    const suffix = "." + row.public_suffix;
    if (
      !row.domain.endsWith(suffix)
      || domainLabels.length !== suffixLabels.length + 1
    ) {
      fail("non-registrable corpus domain: " + row.domain);
    }
    domains.add(row.domain);
  }
  return domains;
}

function validateChecksums(root) {
  const lines = fs.readFileSync(path.join(root, "archives", "SHA256SUMS"), "utf8").trimEnd().split("\n");
  const paths = [];
  for (const line of lines) {
    const match = line.match(/^([0-9a-f]{64})  ([a-zA-Z0-9./-]+)$/);
    if (!match) fail("malformed SHA256SUMS line");
    const relative = match[2];
    if (relative.includes("..") || path.isAbsolute(relative)) fail("unsafe checksum path");
    const absolute = path.join(root, relative);
    if (!fs.statSync(absolute).isFile()) fail(`checksum target is not a file: ${relative}`);
    if (sha256Hex(fs.readFileSync(absolute)) !== match[1]) fail(`checksum mismatch: ${relative}`);
    paths.push(relative);
  }
  const expected = [
    ...fs.readdirSync(path.join(root, "archives", "warc"))
      .filter((name) => name.endsWith(".warc.gz"))
      .map((name) => `archives/warc/${name}`),
    "archives/summary.json", "archives/manifest.csv",
  ].sort();
  if (JSON.stringify(paths) !== JSON.stringify(expected)) fail("checksum coverage/order mismatch");
}

function assertGzipHeader(gzip) {
  if (gzip.length < 18 || gzip[0] !== 0x1f || gzip[1] !== 0x8b || gzip[2] !== 8) fail("invalid gzip header");
  if (gzip[3] !== 0) fail("gzip header contains optional identifying fields");
  if (!gzip.subarray(4, 8).equals(Buffer.alloc(4))) fail("gzip timestamp is not zero");
  if (gzip[9] !== 255) fail("gzip OS byte is not normalized");
}

function integerField(row, name) {
  if (!/^(0|[1-9]\d*)$/.test(row[name])) fail(`invalid ${name}`);
  return Number(row[name]);
}

function mediaType(parsed) {
  const values = headerValues(parsed.httpHeaders, "Content-Type");
  return values.length ? values[values.length - 1].split(";", 1)[0].trim().toLowerCase() : "";
}

function validateTextPrivacy(root) {
  const files = ["archives/README.md", "archives/RIGHTS.md", "archives/format.md", "archives/summary.json", "archives/manifest.csv"];
  for (const relative of files) {
    const text = fs.readFileSync(path.join(root, relative), "utf8");
    if (containsPrivateMetadata(text)) fail(`private metadata in ${relative}`);
  }
}

function sortedObject(object, numeric = false) {
  return Object.fromEntries(Object.entries(object).sort(([a], [b]) =>
    numeric ? Number(a) - Number(b) : Buffer.from(a).compare(Buffer.from(b))));
}

function statusClasses(statusObject) {
  const classes = { "1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 };
  for (const [status, count] of Object.entries(statusObject)) {
    const key = `${String(status)[0]}xx`;
    if (!(key in classes)) fail(`invalid HTTP status class: ${status}`);
    classes[key] += count;
  }
  return classes;
}

function validateReadmeStatusCounts(root, statuses) {
  const readme = fs.readFileSync(path.join(root, "archives", "README.md"), "utf8");
  const match = readme.match(
    /contains (\d+) successful \(2xx\) responses, (\d+) redirects \(3xx\), (\d+) `404`\s+responses, (\d+) `403`, and (\d+) `500` responses/,
  );
  if (!match) fail("archive README status summary is missing or malformed");
  const classes = statusClasses(statuses);
  const actual = match.slice(1).map(Number);
  const expected = [classes["2xx"], classes["3xx"], statuses[404] || 0, statuses[403] || 0, statuses[500] || 0];
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail("archive README status summary drift");
}

export function validatePackage(rootArg = ".") {
  const root = path.resolve(rootArg);
  const manifest = readManifest(root);
  const corpusDomains = readCorpusDomains(root);
  const archiveDir = path.join(root, "archives", "warc");
  const files = fs.readdirSync(archiveDir).sort();
  if (files.some((name) => !name.endsWith(".warc.gz"))) fail("unexpected archive-directory file");
  if (files.length !== manifest.length) fail("archive/manifest count mismatch");
  if (manifest.length !== 219) fail("incomplete collection: expected 219 archives");

  const domains = new Set(), targets = new Set(), payloadHashes = new Set();
  const statuses = {}, mediaTypes = {};
  let compressedBytes = 0, uncompressedBytes = 0, payloadBytes = 0;

  for (let index = 0; index < manifest.length; index += 1) {
    const row = manifest[index];
    if (row.schema_version !== "1") fail("unknown manifest schema version");
    if (index && Buffer.from(manifest[index - 1].domain).compare(Buffer.from(row.domain)) >= 0) fail("manifest domains are not strictly sorted");
    if (domains.has(row.domain)) fail("duplicate domain");
    domains.add(row.domain);
    const expectedFilename = `${row.domain}.warc.gz`;
    if (!corpusDomains.has(row.domain)) {
      fail("archive domain is absent from data/domains.csv: " + row.domain);
    }
    if (files[index] !== expectedFilename) fail("archive filename/order mismatch");
    const gzip = fs.readFileSync(path.join(archiveDir, expectedFilename));
    assertGzipHeader(gzip);
    const uncompressed = zlib.gunzipSync(gzip);
    const parsed = parseWarcRecord(uncompressed);
    verifyCoreDigests(parsed);

    const warcNames = parsed.warcHeaders.map(({ name }) => name);
    if (JSON.stringify(warcNames) !== JSON.stringify(WARC_HEADER_ORDER)) fail("unexpected WARC header set/order");
    if (oneHeader(parsed.warcHeaders, "WARC-Type") !== "response") fail("non-response record");
    if (oneHeader(parsed.warcHeaders, "WARC-Date") !== SENTINEL_DATE) fail("capture time leaked");
    if (oneHeader(parsed.warcHeaders, "Content-Type") !== "application/http; msgtype=response") fail("unexpected WARC content type");
    if (Number(oneHeader(parsed.warcHeaders, "Content-Length")) !== parsed.block.length) fail("WARC Content-Length mismatch");
    const target = oneHeader(parsed.warcHeaders, "WARC-Target-URI");
    const { hostname } = assertPublicHomepageTarget(target);
    if (hostname !== row.domain || target !== row.target_url) fail("target/manifest mismatch");
    if (targets.has(target)) fail("duplicate target URL");
    targets.add(target);

    for (const { name, value } of parsed.httpHeaders) {
      if (isRemovedHttpHeader(name)) fail(`prohibited HTTP metadata: ${name}`);
      if (containsPrivateMetadata(`${name}: ${value}`)) fail("private HTTP metadata");
    }
    const lengths = headerValues(parsed.httpHeaders, "Content-Length");
    if (lengths.length !== 1 || Number(lengths[0]) !== parsed.payload.length) fail("HTTP Content-Length mismatch");
    const statusMatch = parsed.statusLine.match(/^HTTP\/\S+ (\d{3})/);
    if (!statusMatch || statusMatch[1] !== row.http_status) fail("HTTP status mismatch");
    const type = mediaType(parsed);
    if (type !== row.media_type) fail("media type mismatch");
    const recordId = oneHeader(parsed.warcHeaders, "WARC-Record-ID");
    if (recordId !== stableRecordId(target, parsed.block) || recordId !== row.warc_record_id) fail("non-deterministic WARC record ID");

    const warcHash = sha256Hex(gzip), payloadHash = sha256Hex(parsed.payload);
    if (warcHash !== row.warc_sha256 || payloadHash !== row.payload_sha256) fail("manifest hash mismatch");
    if (gzip.length !== integerField(row, "compressed_bytes")) fail("compressed size mismatch");
    if (uncompressed.length !== integerField(row, "uncompressed_bytes")) fail("WARC size mismatch");
    if (parsed.payload.length !== integerField(row, "payload_bytes")) fail("payload size mismatch");

    payloadHashes.add(payloadHash);
    statuses[row.http_status] = (statuses[row.http_status] || 0) + 1;
    mediaTypes[type || "(missing)"] = (mediaTypes[type || "(missing)"] || 0) + 1;
    compressedBytes += gzip.length;
    uncompressedBytes += uncompressed.length;
    payloadBytes += parsed.payload.length;
  }

  const summary = JSON.parse(fs.readFileSync(path.join(root, "archives", "summary.json"), "utf8"));
  const expectedSummary = {
    archive_count: manifest.length,
    distinct_domains: domains.size,
    distinct_target_urls: targets.size,
    distinct_payloads: payloadHashes.size,
    compressed_bytes: compressedBytes,
    uncompressed_bytes: uncompressedBytes,
    payload_bytes: payloadBytes,
  };
  for (const [name, value] of Object.entries(expectedSummary)) {
    if (summary[name] !== value) fail(`summary mismatch: ${name}`);
  }
  if (JSON.stringify(summary.http_statuses) !== JSON.stringify(sortedObject(statuses, true))) fail("status summary mismatch");
  if (JSON.stringify(summary.http_status_classes) !== JSON.stringify(statusClasses(statuses))) fail("status-class summary mismatch");
  if (JSON.stringify(summary.media_types) !== JSON.stringify(sortedObject(mediaTypes))) fail("media summary mismatch");
  if (summary.capture_time_policy?.value !== SENTINEL_DATE) fail("summary time policy mismatch");
  if (summary.response_payload_policy !== "byte-for-byte preserved") fail("payload policy mismatch");

  validateChecksums(root);
  validateTextPrivacy(root);
  validateReadmeStatusCounts(root, statuses);
  return expectedSummary;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    const result = validatePackage(process.argv[2] || ".");
    console.log(`validated ${result.archive_count} archives, ${result.distinct_payloads} distinct payloads`);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
