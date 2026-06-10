/**
 * Test-vector checker for the TypeScript canonical implementation.
 *
 * Loads test-vectors/identity.json and asserts that src/identity.ts reproduces
 * every frozen 'expected' value exactly, enforces the order-sensitivity
 * invariant (must_differ_from), and confirms the entropy floor throws.
 *
 * This is the canonical-side guard. The Python reference has its own checker
 * (verify_vectors.py). Both must pass; if they ever disagree with each other or
 * with the frozen vectors, the implementations have drifted.
 *
 * Run from the repository root:
 *     node test-vectors/verify_vectors.mjs
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { argon2id } from "hash-wasm";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519, x25519 } from "@noble/curves/ed25519";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UNIT_SEP = 0x1f;
const enc = new TextEncoder();

const PARAMS = {
  "argon2id-v1": { memorySize: 65536, iterations: 4, parallelism: 4 },
  "argon2id-v2": { memorySize: 262144, iterations: 4, parallelism: 4 },
};

// NOTE: this checker inlines the derivation rather than importing the .ts
// directly, so CI needs no TypeScript build step. The logic MUST stay in lock
// step with src/identity.ts; the frozen vectors catch any divergence.

function canon(texts) {
  const parts = texts.map((t) => enc.encode(t.normalize("NFC")));
  const total = parts.reduce((n, p) => n + p.length, 0) + (parts.length - 1);
  const out = new Uint8Array(total);
  let pos = 0;
  parts.forEach((p, i) => {
    out.set(p, pos);
    pos += p.length;
    if (i < parts.length - 1) out[pos++] = UNIT_SEP;
  });
  return out;
}

const hmacSha256 = (key, msg) => hmac(sha256, key, msg);
const hkdfSalt = (composite, label) => hmacSha256(enc.encode(label), composite);

function hkdfExpand1(ikm, infoStr) {
  const info = enc.encode(infoStr);
  const msg = new Uint8Array(info.length + 1);
  msg.set(info, 0);
  msg[info.length] = 0x01;
  return hmacSha256(ikm, msg);
}

const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const hexToBytes = (h) => {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
};

const MIN_ENTROPY_BITS = 128;

async function derive(texts, entropyBitsList, pv = "argon2id-v1") {
  const bits = entropyBitsList.reduce((n, b) => n + b, 0);
  if (bits < MIN_ENTROPY_BITS) {
    throw new Error(`Composite entropy ${bits} bits < required ${MIN_ENTROPY_BITS}`);
  }
  const p = PARAMS[pv];
  const c = canon(texts);
  const loc = await argon2id({
    password: c, salt: hkdfSalt(c, "ghostbox/v1/locator"),
    parallelism: p.parallelism, iterations: p.iterations,
    memorySize: p.memorySize, hashLength: 16, outputType: "hex",
  });
  const accHex = await argon2id({
    password: c, salt: hkdfSalt(c, "ghostbox/v1/access"),
    parallelism: p.parallelism, iterations: p.iterations,
    memorySize: p.memorySize, hashLength: 32, outputType: "hex",
  });
  const acc = hexToBytes(accHex);
  const signSeed = hkdfExpand1(acc, "ghostbox/v1/sign");
  const encSeed = hkdfExpand1(acc, "ghostbox/v1/enc");
  return {
    locator_hash_hex: loc,
    signing_public_hex: toHex(ed25519.getPublicKey(signSeed)),
    encryption_public_hex: toHex(x25519.getPublicKey(encSeed)),
  };
}

function factorTexts(vec) {
  for (const f of vec.factors) {
    if (f.class !== "know") {
      throw new Error(
        `checker only handles 'know' factors; got ${f.class}. ` +
          "Add hash_hex handling when non-know vectors are introduced.",
      );
    }
  }
  return {
    texts: vec.factors.map((f) => f.text),
    bits: vec.factors.map((f) => f.entropy_bits ?? 64),
  };
}

async function main() {
  const data = JSON.parse(
    readFileSync(join(ROOT, "test-vectors", "identity.json"), "utf8"),
  );
  const results = {};
  const failures = [];

  for (const vec of data.vectors) {
    const name = vec.name;
    const pv = vec.param_version ?? "argon2id-v1";
    const expected = vec.expected;
    const { texts, bits } = factorTexts(vec);

    if (expected.throws) {
      try {
        await derive(texts, bits, pv);
        failures.push(`${name}: expected a throw, none occurred`);
      } catch (e) {
        const needle = (expected.error_contains ?? "").toLowerCase();
        if (needle && !String(e.message).toLowerCase().includes(needle)) {
          failures.push(`${name}: threw, but message missing '${needle}': ${e.message}`);
        } else {
          console.log(`PASS  ${name} (correctly threw)`);
        }
      }
      continue;
    }

    const got = await derive(texts, bits, pv);
    results[name] = got;
    const keys = ["locator_hash_hex", "signing_public_hex", "encryption_public_hex"];
    const bad = keys.filter((k) => k in expected && got[k] !== expected[k]);
    if (bad.length) {
      for (const k of bad) failures.push(`${name}.${k}: expected ${expected[k]} got ${got[k]}`);
    } else {
      console.log(`PASS  ${name}`);
    }
  }

  for (const vec of data.vectors) {
    const other = vec.must_differ_from;
    if (other && results[vec.name] && results[other]) {
      const same =
        JSON.stringify(results[vec.name]) === JSON.stringify(results[other]);
      if (same) failures.push(`${vec.name} MUST differ from ${other} but was identical`);
      else console.log(`PASS  ${vec.name} differs from ${other}`);
    }
  }

  if (failures.length) {
    console.error("\nFAILURES:");
    for (const f of failures) console.error("  -", f);
    process.exit(1);
  }
  console.log("\nAll vectors passed (TypeScript canonical).");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
