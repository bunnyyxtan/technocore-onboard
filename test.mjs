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
  publicKeyFromDid,
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
      "Contribution: github.com/example/tool — an offline verifier for signed records, zero dependencies, MIT",
      did,
    ),
    "a real contribution line must pass",
  );
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
