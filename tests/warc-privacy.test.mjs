import assert from "node:assert/strict";
import test from "node:test";
import zlib from "node:zlib";
import {
  SENTINEL_DATE,
  assertPublicHomepageTarget,
  buildPublicRecord,
  gzipDeterministic,
  headerValues,
  oneHeader,
  parseWarcRecord,
  sha1Base32,
  stableRecordId,
  verifyCoreDigests,
} from "../scripts/warc-lib.mjs";

function fixture({
  target = "https://example.ye/",
  warcType = "response",
  warcDate = "2024-03-04T05:06:07Z",
  recordId = "<urn:uuid:00000000-0000-4000-8000-000000000001>",
  requestId = "one",
  cookie = "session=one",
  body = Buffer.from("public body Date: 2020-01-02T03:04:05Z", "utf8"),
} = {}) {
  const httpHeaders = [
    "Date: Mon, 04 Mar 2024 05:06:07 GMT",
    `Set-Cookie: ${cookie}`,
    `X-Request-ID: ${requestId}`,
    "CF-RAY: request-specific",
    "X-Forwarded-For: 192.0.2.1",
    "X-Archive-Original-Transfer-Encoding: chunked",
    "Connection: keep-alive",
    "Expires: Mon, 04 Mar 2024 05:07:07 GMT",
    "Last-Modified: Tue, 02 Jan 2024 00:00:00 GMT",
    "Server: fixture",
    "Content-Type: text/plain; charset=utf-8",
    `Content-Length: ${body.length}`,
  ];
  const block = Buffer.concat([
    Buffer.from(`HTTP/1.1 200 OK\r\n${httpHeaders.join("\r\n")}\r\n\r\n`, "latin1"),
    body,
  ]);
  const headers = [
    `WARC-Type: ${warcType}`,
    `WARC-Target-URI: ${target}`,
    `WARC-Date: ${warcDate}`,
    `WARC-Record-ID: ${recordId}`,
    `WARC-Block-Digest: sha1:${sha1Base32(block)}`,
    `WARC-Payload-Digest: sha1:${sha1Base32(body)}`,
    "Content-Type: application/http; msgtype=response",
    `Content-Length: ${block.length}`,
  ];
  const record = Buffer.concat([
    Buffer.from(`WARC/1.0\r\n${headers.join("\r\n")}\r\n\r\n`, "latin1"),
    block,
    Buffer.from("\r\n\r\n"),
  ]);
  return gzipDeterministic(record);
}

test("sanitizer preserves payload and stable response evidence", () => {
  const input = parseWarcRecord(zlib.gunzipSync(fixture()));
  const output = buildPublicRecord(input);
  const parsed = parseWarcRecord(zlib.gunzipSync(output.gzip));
  assert.deepEqual(parsed.payload, input.payload);
  assert.equal(oneHeader(parsed.warcHeaders, "WARC-Date"), SENTINEL_DATE);
  assert.deepEqual(headerValues(parsed.httpHeaders, "Server"), ["fixture"]);
  assert.deepEqual(headerValues(parsed.httpHeaders, "Last-Modified"), [
    "Tue, 02 Jan 2024 00:00:00 GMT",
  ]);
  assert.deepEqual(headerValues(parsed.httpHeaders, "Content-Type"), [
    "text/plain; charset=utf-8",
  ]);
});

test("sanitizer removes collection-bound response metadata", () => {
  const output = buildPublicRecord(parseWarcRecord(zlib.gunzipSync(fixture())));
  const parsed = parseWarcRecord(zlib.gunzipSync(output.gzip));
  const names = parsed.httpHeaders.map(({ name }) => name.toLowerCase());
  for (const prohibited of [
    "date", "set-cookie", "x-request-id", "cf-ray", "x-forwarded-for",
    "x-archive-original-transfer-encoding", "connection", "expires",
  ]) {
    assert.equal(names.includes(prohibited), false, prohibited);
  }
  assert.deepEqual(headerValues(parsed.httpHeaders, "Content-Length"), [
    String(parsed.payload.length),
  ]);
});

test("volatile source metadata cannot change public archive bytes", () => {
  const first = buildPublicRecord(
    parseWarcRecord(zlib.gunzipSync(fixture({ requestId: "one", cookie: "a=1" }))),
  );
  const second = buildPublicRecord(parseWarcRecord(zlib.gunzipSync(fixture({
    warcDate: "2025-09-10T11:12:13Z",
    recordId: "<urn:uuid:ffffffff-ffff-4fff-8fff-ffffffffffff>",
    requestId: "two",
    cookie: "b=2",
  }))));
  assert.deepEqual(first.gzip, second.gzip);
});

test("public record has valid digests and deterministic identifier", () => {
  const output = buildPublicRecord(parseWarcRecord(zlib.gunzipSync(fixture())));
  const parsed = parseWarcRecord(zlib.gunzipSync(output.gzip));
  verifyCoreDigests(parsed);
  assert.equal(
    oneHeader(parsed.warcHeaders, "WARC-Record-ID"),
    stableRecordId(oneHeader(parsed.warcHeaders, "WARC-Target-URI"), parsed.block),
  );
  assert.equal(output.gzip.readUInt32LE(4), 0);
  assert.equal(output.gzip[9], 255);
});

test("timestamp-like public page content is not rewritten", () => {
  const body = Buffer.from("Page updated 2018-01-02T03:04:05Z", "utf8");
  const output = buildPublicRecord(
    parseWarcRecord(zlib.gunzipSync(fixture({ body }))),
  );
  assert.deepEqual(output.payload, body);
});

test("unsafe targets and non-response records are rejected", () => {
  for (const target of [
    "https://user:password@example.ye/",
    "https://example.ye/private",
    "https://example.ye/?session=one",
    "file:///tmp/example.ye",
    "https://example.com/",
  ]) {
    assert.throws(() => assertPublicHomepageTarget(target));
  }
  const request = parseWarcRecord(zlib.gunzipSync(fixture({ warcType: "request" })));
  assert.throws(() => buildPublicRecord(request), /response records/);
});
