import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { sha256Hex } from "./warc-lib.mjs";
import { validatePackage } from "./warc-validate.mjs";

const BUNDLE_NAME = "ye-homepage-warcs-v1.tar.zst";

function fail(message) { throw new Error(message); }

function writeString(header, offset, length, value) {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length > length) fail(`tar field too long: ${value}`);
  bytes.copy(header, offset);
}

function writeOctal(header, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, "0") + "\0";
  if (encoded.length !== length) fail("tar numeric field overflow");
  header.write(encoded, offset, length, "ascii");
}

function tarHeader(name, size) {
  const header = Buffer.alloc(512);
  writeString(header, 0, 100, name);
  writeOctal(header, 100, 8, 0o644);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = "0".charCodeAt(0);
  writeString(header, 257, 6, "ustar\0");
  writeString(header, 263, 2, "00");
  writeOctal(header, 329, 8, 0);
  writeOctal(header, 337, 8, 0);
  const checksum = header.reduce((sum, byte) => sum + byte, 0);
  const encoded = checksum.toString(8).padStart(6, "0") + "\0 ";
  header.write(encoded, 148, 8, "ascii");
  return header;
}

export function createDeterministicTar(entries) {
  const parts = [];
  for (const { name, content } of entries) {
    if (!/^[a-zA-Z0-9./-]+$/.test(name) || name.includes("..") || name.startsWith("/")) {
      fail(`unsafe bundle path: ${name}`);
    }
    parts.push(tarHeader(name, content.length), content);
    const padding = (512 - (content.length % 512)) % 512;
    if (padding) parts.push(Buffer.alloc(padding));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function readString(buffer) {
  const zero = buffer.indexOf(0);
  return buffer.subarray(0, zero < 0 ? buffer.length : zero).toString("utf8");
}

function readOctal(buffer) {
  const value = readString(buffer).trim();
  return value ? Number.parseInt(value, 8) : 0;
}

export function validateDeterministicTar(tar, expectedEntries) {
  let offset = 0;
  for (const expected of expectedEntries) {
    if (offset + 512 > tar.length) fail("truncated tar header");
    const header = tar.subarray(offset, offset + 512);
    offset += 512;
    const name = readString(header.subarray(0, 100));
    const size = readOctal(header.subarray(124, 136));
    const mode = readOctal(header.subarray(100, 108));
    const uid = readOctal(header.subarray(108, 116));
    const gid = readOctal(header.subarray(116, 124));
    const mtime = readOctal(header.subarray(136, 148));
    if (name !== expected.name || size !== expected.content.length) fail("tar entry mismatch");
    if (mode !== 0o644 || uid !== 0 || gid !== 0 || mtime !== 0) fail("non-deterministic tar metadata");
    if (header[156] !== "0".charCodeAt(0)) fail("unexpected tar entry type");
    if (readString(header.subarray(257, 263)) !== "ustar") fail("invalid tar magic");
    const storedChecksum = readOctal(header.subarray(148, 156));
    const checkHeader = Buffer.from(header);
    checkHeader.fill(0x20, 148, 156);
    const computedChecksum = checkHeader.reduce((sum, byte) => sum + byte, 0);
    if (storedChecksum !== computedChecksum) fail("tar header checksum mismatch");
    const content = tar.subarray(offset, offset + size);
    if (!content.equals(expected.content)) fail(`tar content mismatch: ${name}`);
    offset += size + ((512 - (size % 512)) % 512);
  }
  if (tar.length - offset !== 1024 || !tar.subarray(offset).equals(Buffer.alloc(1024))) {
    fail("tar end marker mismatch");
  }
}

function runZstd(args, input) {
  const result = spawnSync("zstd", args, {
    input,
    maxBuffer: 64 * 1024 * 1024,
    encoding: null,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) fail(`zstd failed with status ${result.status}`);
  return result.stdout;
}

function bundleEntries(root) {
  const relativePaths = [
    "archives/README.md",
    "archives/RIGHTS.md",
    "archives/SHA256SUMS",
    "archives/summary.json",
    "archives/manifest.csv",
    "archives/format.md",
    ...fs.readdirSync(path.join(root, "archives", "warc"))
      .filter((name) => name.endsWith(".warc.gz"))
      .map((name) => `archives/warc/${name}`),
  ].sort();
  return relativePaths.map((name) => ({
    name,
    content: fs.readFileSync(path.join(root, name)),
  }));
}

export function buildBundle(rootArg = ".", outputArg) {
  const root = path.resolve(rootArg);
  if (!outputArg) fail("an external release-asset output directory is required");
  const output = path.resolve(outputArg);
  validatePackage(root);
  const entries = bundleEntries(root);
  const tar = createDeterministicTar(entries);
  validateDeterministicTar(tar, entries);
  const compressed = runZstd(["-19", "-T1", "-q", "-c"], tar);
  const roundTrip = runZstd(["-d", "-q", "-c"], compressed);
  if (!roundTrip.equals(tar)) fail("zstd round-trip mismatch");
  validateDeterministicTar(roundTrip, entries);

  fs.mkdirSync(output, { recursive: true });
  const bundlePath = path.join(output, BUNDLE_NAME);
  fs.writeFileSync(bundlePath, compressed, { mode: 0o644 });
  const hash = sha256Hex(compressed);
  const sidecarName = `${BUNDLE_NAME}.sha256`;
  fs.writeFileSync(path.join(output, sidecarName), `${hash}  ${BUNDLE_NAME}\n`, { mode: 0o644 });
  return {
    name: BUNDLE_NAME,
    checksum_name: sidecarName,
    sha256: hash,
    entries: entries.length,
    compressed_bytes: compressed.length,
    uncompressed_bytes: tar.length,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  try {
    if (!process.argv[3]) {
      console.error("Usage: node scripts/warc-bundle.mjs <repository-root> <external-output-directory>");
      process.exit(2);
    }
    const result = buildBundle(process.argv[2] || ".", process.argv[3]);
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
