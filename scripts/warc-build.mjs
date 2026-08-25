import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import {
  SENTINEL_DATE,
  assertPublicHomepageTarget,
  buildPublicRecord,
  parseWarcRecord,
  sha256Hex,
  verifyCoreDigests,
} from "./warc-lib.mjs";

const [inputArg, outputArg = "."] = process.argv.slice(2);
if (!inputArg) {
  console.error("Usage: node scripts/warc-build.mjs <private-input-directory> [repository-root]");
  process.exit(2);
}

const input = path.resolve(inputArg);
const output = path.resolve(outputArg);
if (!fs.statSync(input).isDirectory()) throw new Error("input is not a directory");
if (input === output || input.startsWith(`${output}${path.sep}`)) {
  throw new Error("private input must not be inside the public output tree");
}

const archiveDir = path.join(output, "archives", "warc");
const dataDir = path.join(output, "archives");
fs.mkdirSync(archiveDir, { recursive: true });
fs.mkdirSync(dataDir, { recursive: true });

const inputs = fs.readdirSync(input).filter((name) => name.endsWith(".warc.gz")).sort();
if (inputs.length === 0) throw new Error("no WARC inputs found");

const manifest = [];
const statuses = {};
const mediaTypes = {};
const payloadHashes = new Set();
let compressedBytes = 0;
let uncompressedBytes = 0;
let payloadBytes = 0;

for (const filename of inputs) {
  if (!/^[a-z0-9][a-z0-9.-]*\.ye\.warc\.gz$/.test(filename)) {
    throw new Error(`unsafe archive filename: ${filename}`);
  }
  const sourceGzip = fs.readFileSync(path.join(input, filename));
  const parsed = parseWarcRecord(zlib.gunzipSync(sourceGzip));
  verifyCoreDigests(parsed);
  const built = buildPublicRecord(parsed);
  if (!built.payload.equals(parsed.payload)) throw new Error("payload changed during build");

  const { hostname } = assertPublicHomepageTarget(built.target);
  const expectedFilename = `${hostname}.warc.gz`;
  if (filename !== expectedFilename) throw new Error("filename does not match target hostname");

  const outputPath = path.join(archiveDir, filename);
  fs.writeFileSync(outputPath, built.gzip, { mode: 0o644 });
  const reparsed = parseWarcRecord(zlib.gunzipSync(fs.readFileSync(outputPath)));
  verifyCoreDigests(reparsed);
  if (!reparsed.payload.equals(parsed.payload)) throw new Error("written payload mismatch");

  const status = Number((parsed.statusLine.match(/^HTTP\/\S+ (\d{3})/) || [])[1]);
  if (!Number.isInteger(status)) throw new Error("missing HTTP status");
  const contentTypes = built.httpHeaders
    .filter(({ name }) => name.toLowerCase() === "content-type")
    .map(({ value }) => value);
  const mediaType = contentTypes.length
    ? contentTypes[contentTypes.length - 1].split(";", 1)[0].trim().toLowerCase()
    : "";
  const warcHash = sha256Hex(built.gzip);
  const payloadHash = sha256Hex(parsed.payload);
  payloadHashes.add(payloadHash);
  statuses[status] = (statuses[status] || 0) + 1;
  mediaTypes[mediaType || "(missing)"] = (mediaTypes[mediaType || "(missing)"] || 0) + 1;
  compressedBytes += built.gzip.length;
  uncompressedBytes += built.uncompressed.length;
  payloadBytes += parsed.payload.length;
  manifest.push({
    schema_version: "1",
    domain: hostname,
    target_url: built.target,
    http_status: String(status),
    media_type: mediaType,
    compressed_bytes: String(built.gzip.length),
    uncompressed_bytes: String(built.uncompressed.length),
    payload_bytes: String(parsed.payload.length),
    warc_sha256: warcHash,
    payload_sha256: payloadHash,
    warc_record_id: built.recordId,
  });
}

const outputNames = fs.readdirSync(archiveDir).filter((name) => name.endsWith(".warc.gz")).sort();
if (JSON.stringify(outputNames) !== JSON.stringify(inputs)) {
  throw new Error("unexpected or stale WARC files in output directory");
}

const fields = [
  "schema_version",
  "domain",
  "target_url",
  "http_status",
  "media_type",
  "compressed_bytes",
  "uncompressed_bytes",
  "payload_bytes",
  "warc_sha256",
  "payload_sha256",
  "warc_record_id",
];

function csv(value) {
  const string = String(value);
  return /[",\r\n]/.test(string) ? `"${string.replaceAll('"', '""')}"` : string;
}

const manifestText = [
  fields.join(","),
  ...manifest.map((row) => fields.map((field) => csv(row[field])).join(",")),
].join("\n") + "\n";
const manifestPath = path.join(dataDir, "manifest.csv");
fs.writeFileSync(manifestPath, manifestText, { mode: 0o644 });

function sortedObject(object, numeric = false) {
  return Object.fromEntries(
    Object.entries(object).sort(([a], [b]) =>
      numeric ? Number(a) - Number(b) : Buffer.from(a).compare(Buffer.from(b)),
    ),
  );
}

function statusClasses(statusObject) {
  const classes = { "1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0 };
  for (const [status, count] of Object.entries(statusObject)) {
    const key = `${String(status)[0]}xx`;
    if (!(key in classes)) throw new Error(`invalid HTTP status class: ${status}`);
    classes[key] += count;
  }
  return classes;
}

const summary = {
  schema_version: 1,
  scope: "all homepage WARCs currently available to the project",
  archive_count: manifest.length,
  distinct_domains: new Set(manifest.map((row) => row.domain)).size,
  distinct_target_urls: new Set(manifest.map((row) => row.target_url)).size,
  distinct_payloads: payloadHashes.size,
  compressed_bytes: compressedBytes,
  uncompressed_bytes: uncompressedBytes,
  payload_bytes: payloadBytes,
  http_statuses: sortedObject(statuses, true),
  http_status_classes: statusClasses(statuses),
  media_types: sortedObject(mediaTypes),
  warc_version: "WARC/1.0",
  record_type: "response",
  records_per_file: 1,
  capture_time_policy: {
    value: SENTINEL_DATE,
    interpretation: "privacy sentinel; not an acquisition timestamp",
  },
  response_payload_policy: "byte-for-byte preserved",
};
const summaryPath = path.join(dataDir, "summary.json");
fs.writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`, { mode: 0o644 });

const checksumTargets = [
  ...manifest.map((row) => `archives/warc/${row.domain}.warc.gz`),
  "archives/summary.json",
  "archives/manifest.csv",
].sort();
const checksums = checksumTargets
  .map((relative) => `${sha256Hex(fs.readFileSync(path.join(output, relative)))}  ${relative}`)
  .join("\n") + "\n";
fs.writeFileSync(path.join(output, "archives", "SHA256SUMS"), checksums, { mode: 0o644 });

console.log(JSON.stringify({
  archives: manifest.length,
  distinct_domains: summary.distinct_domains,
  distinct_payloads: summary.distinct_payloads,
  compressed_bytes: summary.compressed_bytes,
  payload_bytes: summary.payload_bytes,
}));
