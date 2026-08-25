import assert from "node:assert/strict";
import test from "node:test";
import {
  createDeterministicTar,
  validateDeterministicTar,
} from "../scripts/warc-bundle.mjs";

const entries = [
  { name: "archives/warc/a.ye.warc.gz", content: Buffer.from([1, 2, 3]) },
  { name: "data/summary.json", content: Buffer.from("{}\n", "utf8") },
];

test("tar bundle bytes and metadata are deterministic", () => {
  const first = createDeterministicTar(entries);
  const second = createDeterministicTar(entries);
  assert.deepEqual(first, second);
  validateDeterministicTar(first, entries);
  assert.equal(
    first.subarray(136, 148).toString("ascii"),
    "00000000000\0",
  );
});

test("tar validator rejects content corruption", () => {
  const tar = createDeterministicTar(entries);
  const corrupted = Buffer.from(tar);
  corrupted[512] ^= 0xff;
  assert.throws(
    () => validateDeterministicTar(corrupted, entries),
    /content mismatch/,
  );
});

test("tar generator rejects unsafe paths", () => {
  assert.throws(
    () => createDeterministicTar([{ name: "../private", content: Buffer.alloc(0) }]),
    /unsafe bundle path/,
  );
  assert.throws(
    () => createDeterministicTar([{ name: "/absolute", content: Buffer.alloc(0) }]),
    /unsafe bundle path/,
  );
});
