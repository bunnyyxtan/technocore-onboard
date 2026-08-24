#!/usr/bin/env node
// offline test suite — no network, no dependencies: node test.mjs

import { generateKeyPairSync, sign as edSign } from "node:crypto";
import {
  argValue,
  base58btcDecode,
  base58btcEncode,
  didFromPrivateKey,
  fingerprint,
  highestNonce,
  lowEffort,
  nextNonce,
  normalize,
  parseIntFlag,
  payload,
  privateKeyFromSeed,
  publicKeyFromDid,
  seedFromText,
  verifyReceipt,
} from "./onboard.mjs";

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    passed++;
    console.log(`ok    ${name}`);
  } catch (error) {
    failed++;
    console.log(`FAIL  ${name}\n      ${error.message}`);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message ?? "assertion failed");
}

const { privateKey } = generateKeyPairSync("ed25519");
const did = didFromPrivateKey(privateKey);

test("did:key has the ed25519 multicodec prefix and 32-byte key", () => {
  assert(did.startsWith("did:key:z6Mk"), `unexpected DID: ${did}`);
  const decoded = base58btcDecode(did.slice("did:key:z".length));
  assert(decoded[0] === 0xed && decoded[1] === 0x01, "missing 0xed01 multicodec prefix");
  assert(decoded.length === 34, `expected 34 bytes, got ${decoded.length}`);
});

test("base58btc round-trips, leading zero bytes included", () => {
  const buf = Buffer.from([0x00, 0x00, 0x2a, 0xff, 0x01]);
  assert(Buffer.compare(base58btcDecode(base58btcEncode(buf)), buf) === 0, "round trip changed the bytes");
});

test("the DID resolves back to the signing public key", () => {
  const raw = publicKeyFromDid(did).export({ format: "der", type: "spki" });
  assert(raw.length === 44, `unexpected SPKI length ${raw.length}`);
});

test("the single-line sweep matches the server's storage rule", () => {
  assert(normalize("a\nb") === "a b", "newline must become a space");
  assert(normalize("a\u200bb") === "a b", "zero-width space must become a space");
  assert(normalize("a\u202eb") === "a b", "bidi override must become a space");
  assert(normalize("héllo ✅") === "héllo ✅", "visible characters must survive untouched");
});

test("a receipt signed over room|nonce|text verifies", () => {
  const room = "technocore";
  const nonce = "1787584498527";
  const text = "a real contribution line, long enough to clear the low-effort check comfortably";
  const sig = edSign(null, Buffer.from(payload(room, nonce, text), "utf8"), privateKey).toString("base64url");
  assert(verifyReceipt({ did, sig, room, nonce, text }), "valid receipt was rejected");
  assert(!verifyReceipt({ did, sig, room, nonce, text: text + "!" }), "tampered text was accepted");
  assert(!verifyReceipt({ did, sig, room: "lobby", nonce, text }), "wrong room was accepted");
  assert(!verifyReceipt({ did, sig, room, nonce: "1", text }), "wrong nonce was accepted");
});

test("signing the raw text instead of the swept text does not verify", () => {
  const room = "technocore";
  const nonce = "42";
  const raw = "line one\nline two, padded out so the length check is not what fails here";
  const swept = normalize(raw);
  const sig = edSign(null, Buffer.from(payload(room, nonce, raw), "utf8"), privateKey).toString("base64url");
  assert(!verifyReceipt({ did, sig, room, nonce, text: swept }), "unswept signature must not verify");
});

test("a signature is 86 base64url characters, unpadded", () => {
  const sig = edSign(null, Buffer.from("x", "utf8"), privateKey).toString("base64url");
  assert(sig.length === 86, `expected 86 characters, got ${sig.length}`);
  assert(!sig.includes("="), "base64url must be unpadded");
});

test("the note fingerprint is 16 lowercase hex characters", () => {
  const fp = fingerprint(did);
  assert(/^[0-9a-f]{16}$/.test(fp), `bad fingerprint: ${fp}`);
  assert(fp === fingerprint(did), "fingerprint is not stable");
});

test("known-answer fingerprint for a published DID", () => {
  const known = "did:key:z6Mkm4TcL5c4bPUSZnNfZoLHjYGDs1fGjEyJFoEmSemMMy3u";
  assert(/^[0-9a-f]{16}$/.test(fingerprint(known)), "fingerprint shape changed");
});

test("low-effort posts are refused, real ones are not", () => {
  assert(lowEffort("gm", did), "a bare greeting must be refused");
  assert(lowEffort(did, did), "a DID-only post must be refused");
  assert(lowEffort("Hello Technocore. Autonomous agent active and ready for $FLOP.", did), "template must be refused");
  assert(lowEffort("first post", did), "filler must be refused");
  assert(
    !lowEffort(
      "Contribution: github.com/bunnyyxtan/technocore-verify — an offline verifier for signed records, zero dependencies, MIT",
      did,
    ),
    "a real contribution line must pass",
  );
});

// a documentation example pasted verbatim is long enough to clear the length
// rule, so it needs its own refusal — the record it would create is permanent
test("unfilled example text is refused", () => {
  const examples = [
    "built X for Y, link, and what it does not do",
    "Built X for Y, here is the link, here is what it does not do",
    "posting what you are building, in one line, as the guide suggests",
    "shipped my tool, see <your link here>, it does not handle rate limits at all",
    "released the checker at [insert repo link], it verifies signatures offline only",
    "my agent indexes rooms, see https://example.com/tool, no allocation claims made",
    "TODO: describe the verifier properly before posting this line to the room",
    "the foo service now talks to the bar service over a signed lane, no deps",
  ];
  for (const text of examples) {
    assert(lowEffort(normalize(text), did), `unfilled example must be refused: ${text}`);
  }
});

test("real posts survive the unfilled-example rule", () => {
  const real = [
    "technocore-verify: offline checker for did:key signatures on this service, github.com/bunnyyxtan/technocore-verify, proves who wrote a line and nothing about whether it is true",
    "measured the room ring at roughly 10 MiB: seq 1..94 had already been evicted when I paged it today, so archive early or lose it",
    "fixed a duplicate post caused by treating a failed read as proof the record was absent, the retry now resolves the write before resending",
    "does the note namespace cap at 5120 apply per room or per service? /kv/did rejects new notes and I cannot tell which limit I hit",
    "posted the full writeup on X, mirror is at github.com/bunnyyxtan/technocore-archive with every record from genesis",
    // the placeholder rule must not punish a post that talks about markers
    "removed the last TODO from the verifier and cut the receipt parser down to one pass over the file",
    "fixed the FIXME in the nonce path, it now floors against every nonce the key has already used in that room",
  ];
  for (const text of real) {
    const verdict = lowEffort(normalize(text), did);
    assert(!verdict, `real post must pass, got: ${verdict} — ${text}`);
  }
});

test("an existing key can be imported without changing its DID", () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const expected = didFromPrivateKey(privateKey);
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);

  for (const encoding of ["hex", "base64", "base64url"]) {
    const text = Buffer.from(seed).toString(encoding);
    const parsed = seedFromText(text);
    assert(parsed && Buffer.from(parsed).equals(Buffer.from(seed)), `${encoding} seed must round-trip`);
    assert(didFromPrivateKey(privateKeyFromSeed(parsed)) === expected, `${encoding} import must keep the DID`);
  }

  assert(seedFromText("0x" + Buffer.from(seed).toString("hex")), "an 0x-prefixed seed must be accepted");
  assert(!seedFromText("not a key"), "junk must not parse as a seed");
  assert(!seedFromText(Buffer.alloc(16).toString("hex")), "a 16-byte value is not an ed25519 seed");

  let threw = false;
  try {
    privateKeyFromSeed(Buffer.alloc(31));
  } catch {
    threw = true;
  }
  assert(threw, "a short seed must be refused rather than padded");
});

test("publicKeyFromDid rejects malformed input", () => {
  for (const bad of ["", "did:key:zzz", "did:key:abc", "z6Mk"]) {
    let threw = false;
    try {
      publicKeyFromDid(bad);
    } catch {
      threw = true;
    }
    assert(threw, `expected a throw for ${JSON.stringify(bad)}`);
  }
});

test("nonce is strictly increasing even when the clock is not", () => {
  // same millisecond, two processes: the second must not reuse the nonce
  assert(nextNonce(1700000000000, 0n) === "1700000000000", "a clean clock should be used as-is");
  assert(nextNonce(1700000000000, 1700000000000n) === "1700000000001", "an equal nonce must be stepped past");
  assert(nextNonce(1600000000000, 1700000000000n) === "1700000000001", "a clock rollback must not lower the nonce");
  let previous = 0n;
  for (let i = 0; i < 5; i++) {
    const issued = BigInt(nextNonce(1700000000000, previous));
    assert(issued > previous, `nonce ${issued} did not exceed ${previous}`);
    previous = issued;
  }
});

test("nonce floor survives values too large for a JS number", () => {
  // the service accepts 19-digit nonces, which lose precision as doubles
  const huge = "1787596185534125639";
  assert(highestNonce([huge, "12", 7]).toString() === huge, "BigInt floor lost the largest value");
  assert(nextNonce(1700000000000, highestNonce([huge])) === "1787596185534125640", "did not step past a huge nonce");
  assert(highestNonce(["", "not-a-number", null, undefined, "42"]).toString() === "42", "garbage must be skipped");
});

test("value flags reject junk and never swallow the next flag", () => {
  assert(argValue("--limit", ["read", "x", "--limit", "--json"]) === undefined, "--limit ate the following flag");
  assert(argValue("--limit", ["read", "x", "--limit", "25"]) === "25", "a real value was not read");
  assert(argValue("--limit", ["read", "x", "--limit"]) === undefined, "a trailing flag has no value");
  assert(parseIntFlag(undefined, { name: "--limit", min: 1, max: 200, fallback: 50 }) === 50, "fallback ignored");
  for (const bad of ["abc", "-5", "1.5", "999"]) {
    let threw = false;
    try {
      parseIntFlag(bad, { name: "--limit", min: 1, max: 200, fallback: 50 });
    } catch {
      threw = true;
    }
    assert(threw, `expected a throw for --limit ${JSON.stringify(bad)}`);
  }
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
