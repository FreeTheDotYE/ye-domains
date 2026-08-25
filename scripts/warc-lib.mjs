import crypto from "node:crypto";
import zlib from "node:zlib";

export const SENTINEL_DATE = "1970-01-01T00:00:00Z";
export const WARC_HEADER_ORDER = [
  "WARC-Type",
  "WARC-Target-URI",
  "WARC-Date",
  "WARC-Record-ID",
  "WARC-Block-Digest",
  "WARC-Payload-Digest",
  "Content-Type",
  "Content-Length",
];

const HTTP_REMOVE_EXACT = new Set([
  "age",
  "authorization",
  "cf-connecting-ip",
  "cf-ray",
  "client-ip",
  "connection",
  "cookie",
  "date",
  "expires",
  "forwarded",
  "from",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "referer",
  "retry-after",
  "server-timing",
  "set-cookie",
  "set-cookie2",
  "te",
  "trailer",
  "traceparent",
  "tracestate",
  "transfer-encoding",
  "true-client-ip",
  "upgrade",
  "user-agent",
  "via",
  "x-amzn-trace-id",
  "x-contextid",
  "x-iinfo",
  "x-real-ip",
  "x-vercel-id",
]);

const HTTP_REMOVE_PATTERNS = [
  /^x-archive-/,
  /^x-forwarded-/,
  /^x-client-/,
  /^x-ratelimit-/,
  /^x-(?:.*-)?request-id$/,
];

const HEADER_NAME = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const PRIVATE_METADATA =
  /(?:\/home\/|\\Users\\|accounts\.txt|github_pat_[A-Za-z0-9_]+|ghp_[A-Za-z0-9]+|-----BEGIN [A-Z ]*PRIVATE KEY-----|authorization\s*:\s*bearer\s+)/i;

function fail(message) {
  throw new Error(message);
}

function separatorIndex(buffer) {
  const index = buffer.indexOf(Buffer.from("\r\n\r\n"));
  if (index < 0) fail("missing CRLF header separator");
  return index;
}

function parseHeaderLines(lines, context) {
  return lines.map((line) => {
    const colon = line.indexOf(":");
    if (colon <= 0) fail(`malformed ${context} header`);
    const name = line.slice(0, colon).trim();
    const value = line.slice(colon + 1).trim();
    if (!HEADER_NAME.test(name)) fail(`invalid ${context} header name`);
    if (/[\r\n]/.test(value)) fail(`invalid ${context} header value`);
    return { name, value };
  });
}

export function headerValues(headers, wanted) {
  const lower = wanted.toLowerCase();
  return headers
    .filter(({ name }) => name.toLowerCase() === lower)
    .map(({ value }) => value);
}

export function oneHeader(headers, wanted) {
  const values = headerValues(headers, wanted);
  if (values.length !== 1) fail(`expected one ${wanted} header`);
  return values[0];
}

export function parseWarcRecord(uncompressed) {
  if (!Buffer.isBuffer(uncompressed)) fail("WARC input must be a Buffer");
  const warcSeparator = separatorIndex(uncompressed);
  const warcLines = uncompressed
    .subarray(0, warcSeparator)
    .toString("latin1")
    .split("\r\n");
  const version = warcLines.shift();
  if (version !== "WARC/1.0") fail("only WARC/1.0 is supported");
  const warcHeaders = parseHeaderLines(warcLines, "WARC");
  const contentLength = Number(oneHeader(warcHeaders, "Content-Length"));
  if (!Number.isSafeInteger(contentLength) || contentLength < 0) {
    fail("invalid WARC Content-Length");
  }
  const blockStart = warcSeparator + 4;
  const blockEnd = blockStart + contentLength;
  if (blockEnd > uncompressed.length) fail("truncated WARC block");
  const trailer = uncompressed.subarray(blockEnd);
  if (!trailer.equals(Buffer.from("\r\n\r\n"))) {
    fail("unexpected bytes after WARC record");
  }
  const block = uncompressed.subarray(blockStart, blockEnd);
  const httpSeparator = separatorIndex(block);
  const httpLines = block
    .subarray(0, httpSeparator)
    .toString("latin1")
    .split("\r\n");
  const statusLine = httpLines.shift();
  if (!/^HTTP\/\d(?:\.\d)? [1-5]\d\d(?: .*)?$/.test(statusLine)) {
    fail("invalid HTTP response status line");
  }
  const httpHeaders = parseHeaderLines(httpLines, "HTTP");
  const payload = block.subarray(httpSeparator + 4);
  return { version, warcHeaders, block, statusLine, httpHeaders, payload };
}

export function targetUrl(parsed) {
  return oneHeader(parsed.warcHeaders, "WARC-Target-URI");
}

export function assertPublicHomepageTarget(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    fail("invalid WARC target URL");
  }
  if (!["http:", "https:"].includes(url.protocol)) fail("target must use HTTP(S)");
  if (url.username || url.password) fail("target URL contains credentials");
  if (url.port || url.hash || url.search) fail("target URL contains private context");
  if (url.pathname !== "/") fail("target URL is not a homepage root");
  const hostname = url.hostname.toLowerCase();
  if (!hostname.endsWith(".ye")) fail("target is outside the .ye namespace");
  if (!/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.ye$/.test(hostname)) {
    fail("target hostname is not a safe ASCII domain");
  }
  return { url, hostname };
}

export function isRemovedHttpHeader(name) {
  const lower = name.toLowerCase();
  return (
    HTTP_REMOVE_EXACT.has(lower) ||
    HTTP_REMOVE_PATTERNS.some((pattern) => pattern.test(lower))
  );
}

export function sanitizeHttpHeaders(headers, payloadLength) {
  const safe = [];
  for (const { name, value } of headers) {
    if (!HEADER_NAME.test(name) || /[\r\n]/.test(value)) {
      fail("unsafe HTTP header syntax");
    }
    if (name.toLowerCase() === "content-length" || isRemovedHttpHeader(name)) continue;
    if (PRIVATE_METADATA.test(`${name}: ${value}`)) {
      fail("private metadata pattern in retained HTTP header");
    }
    safe.push({ name, value });
  }
  safe.push({ name: "Content-Length", value: String(payloadLength) });
  return safe;
}

export function sha256Hex(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

export function sha1Base32(buffer) {
  const digest = crypto.createHash("sha1").update(buffer).digest();
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let output = "";
  let accumulator = 0;
  let bits = 0;
  for (const byte of digest) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(accumulator >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(accumulator << (5 - bits)) & 31];
  return output;
}

export function stableRecordId(target, block) {
  const seed = Buffer.concat([
    Buffer.from(target, "utf8"),
    Buffer.from([0]),
    crypto.createHash("sha256").update(block).digest(),
  ]);
  const bytes = Buffer.from(crypto.createHash("sha256").update(seed).digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  return `<urn:uuid:${uuid}>`;
}

function serializeHeaders(headers) {
  return headers.map(({ name, value }) => `${name}: ${value}`).join("\r\n");
}

export function gzipDeterministic(uncompressed) {
  const gzip = zlib.gzipSync(uncompressed, { level: 9, mtime: 0 });
  gzip.fill(0, 4, 8);
  gzip[9] = 255;
  return gzip;
}

export function buildPublicRecord(parsed) {
  if (oneHeader(parsed.warcHeaders, "WARC-Type") !== "response") {
    fail("only response records can be published");
  }
  const target = targetUrl(parsed);
  assertPublicHomepageTarget(target);
  const safeHeaders = sanitizeHttpHeaders(parsed.httpHeaders, parsed.payload.length);
  const httpHead = Buffer.from(
    `${parsed.statusLine}\r\n${serializeHeaders(safeHeaders)}\r\n\r\n`,
    "latin1",
  );
  const block = Buffer.concat([httpHead, parsed.payload]);
  const recordId = stableRecordId(target, block);
  const warcHeaders = [
    { name: "WARC-Type", value: "response" },
    { name: "WARC-Target-URI", value: target },
    { name: "WARC-Date", value: SENTINEL_DATE },
    { name: "WARC-Record-ID", value: recordId },
    { name: "WARC-Block-Digest", value: `sha1:${sha1Base32(block)}` },
    { name: "WARC-Payload-Digest", value: `sha1:${sha1Base32(parsed.payload)}` },
    { name: "Content-Type", value: "application/http; msgtype=response" },
    { name: "Content-Length", value: String(block.length) },
  ];
  const warcHead = Buffer.from(
    `WARC/1.0\r\n${serializeHeaders(warcHeaders)}\r\n\r\n`,
    "latin1",
  );
  const uncompressed = Buffer.concat([warcHead, block, Buffer.from("\r\n\r\n")]);
  return {
    gzip: gzipDeterministic(uncompressed),
    uncompressed,
    block,
    payload: parsed.payload,
    httpHeaders: safeHeaders,
    target,
    recordId,
  };
}

export function verifyCoreDigests(parsed) {
  const block = oneHeader(parsed.warcHeaders, "WARC-Block-Digest");
  const payload = oneHeader(parsed.warcHeaders, "WARC-Payload-Digest");
  if (block.toUpperCase() !== `SHA1:${sha1Base32(parsed.block)}`) {
    fail("invalid WARC block digest");
  }
  if (payload.toUpperCase() !== `SHA1:${sha1Base32(parsed.payload)}`) {
    fail("invalid WARC payload digest");
  }
}

export function containsPrivateMetadata(value) {
  return PRIVATE_METADATA.test(value);
}
