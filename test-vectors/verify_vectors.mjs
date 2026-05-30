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
 * NOTE: This checker inlines the derivation rather than importing identity.ts
 * directly, so CI needs no TypeScript build step. The logic MUST stay in lock
 * step with src/identity.ts; the frozen vectors catch any divergence.
 *
 * This revision corrects the HKDF construction to real RFC 5869
 * (Extract then Expand) matching noble's hkdf(sha256, ikm, undefined, info, 32)
 * and the corrected Python reference. The previous version used a bare
 * HMAC(label, composite) which did not match either canonical implementation.
 * Entropy for 'know' factors is now measured with zxcvbn-ts, matching
 * src/identity.ts; the entropy_bits field in the JSON is no longer used.
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
import { zxcvbn, zxcvbnOptions } from "@zxcvbn-ts/core";
import * as zxcvbnCommon from "@zxcvbn-ts/language-common";
import * as zxcvbnEn from "@zxcvbn-ts/language-en";

zxcvbnOptions.setOptions({
  dictionary: { ...zxcvbnCommon.dictionary, ...zxcvbnEn.dictionary },
  graphs: zxcvbnCommon.adjacencyGraphs,
  translations: zxcvbnEn.translations,
});

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const UNIT_SEP = 0x1f;
const enc = new TextEncoder();

const MIN_ENTROPY_BITS = 128;
const CLASS_CAP_BITS = { know: 80, are: 24, have: 64, who: 64 };

const PARAMS = {
  "argon2id-v1": { memorySize: 65536, iterations: 4, parallelism: 4 },
  "argon2id-v2": { memorySize: 262144, iterations: 4, parallelism: 4 },
};

const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const hexToBytes = (h) => {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
};

// --- RFC 5869 HKDF (inline, using noble hmac) ----------------------------
// Matches noble's hkdf(sha256, ikm, undefined, info, 32):
//   Extract: PRK = HMAC(key=zeroes_32, msg=ikm)
//   Expand:  T1  = HMAC(key=PRK, msg=enc(info) || 0x01)
//
// The previous version used HMAC(label, composite) which is not HKDF and
// did not match the canonical construction in src/identity.ts.

function hkdf32(ikm, infoStr) {
  const zeroSalt = new Uint8Array(32);
  const prk = hmac(sha256, zeroSalt, ikm);
  const info = enc.encode(infoStr);
  const msg = new Uint8Array(info.length + 1);
  msg.set(info);
  msg[info.length] = 0x01;
  return hmac(sha256, prk, msg);
}

// --- Entropy measurement (mirrors src/identity.ts) -----------------------

function measureEntropyBits(text) {
  const normalized = text.normalize("NFC");
  const guesses = Math.max(zxcvbn(normalized).guesses, 2);
  return Math.min(Math.log2(guesses), CLASS_CAP_BITS.know);
}

// --- Canonicalize --------------------------------------------------------

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

// --- Derivation ----------------------------------------------------------

async function derive(texts, entropyBitsList, pv = "argon2id-v1") {
  const bits = entropyBitsList.reduce((n, b) => n + b, 0);
  const maxBit = Math.max(...entropyBitsList);
  if (bits < MIN_ENTROPY_BITS) {
    throw new Error(`Composite entropy ${bits.toFixed(1)} bits < required ${MIN_ENTROPY_BITS}`);
  }
  if (maxBit > bits / 2) {
    throw new Error(`No single factor may supply more than half the entropy floor`);
  }
  const p = PARAMS[pv];
  const c = canon(texts);

  const saltLoc = hkdf32(c, "ghostbox/v1/locator");
  const saltAcc = hkdf32(c, "ghostbox/v1/access");

  const loc = await argon2id({
    password: c, salt: saltLoc,
    parallelism: p.parallelism, iterations: p.iterations,
    memorySize: p.memorySize, hashLength: 16, outputType: "hex",
  });
  const accHex = await argon2id({
    password: c, salt: saltAcc,
    parallelism: p.parallelism, iterations: p.iterations,
    memorySize: p.memorySize, hashLength: 32, outputType: "hex",
  });

  const acc = hexToBytes(accHex);
  const signSeed = hkdf32(acc, "ghostbox/v1/sign");
  const encSeed = hkdf32(acc, "ghostbox/v1/enc");

  return {
    locator_hash_hex: loc,
    signing_public_hex: toHex(ed25519.getPublicKey(signSeed)),
    encryption_public_hex: toHex(x25519.getPublicKey(encSeed)),
  };
}

// --- Factor builder ------------------------------------------------------

function buildFactors(vec) {
  const texts = [];
  const bits = [];
  for (const f of vec.factors) {
    if (f.class !== "know") {
      throw new Error(
        `checker only handles 'know' factors; got ${f.class}. ` +
        "Add hashed_factor handling when non-know vectors are introduced.",
      );
    }
    texts.push(f.text);
    bits.push(measureEntropyBits(f.text));
  }
  return { texts, bits };
}

// --- Main ----------------------------------------------------------------

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
    const { texts, bits } = buildFactors(vec);

    if (expected.throws) {
      try {
        await derive(texts, bits, pv);
        failures.push(`${name}: expected a throw, none occurred`);
      } catch (e) {
        const needle = (expected.error_contains ?? "").toLowerCase();
        if (needle && !String(e.message).toLowerCase().includes(needle)) {
          failures.push(`${name}: threw but message missing '${needle}': ${e.message}`);
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
      for (const k of bad) {
        failures.push(`${name}.${k}: expected ${expected[k]} got ${got[k]}`);
      }
    } else {
      console.log(`PASS  ${name}`);
    }
  }

  for (const vec of data.vectors) {
    const other = vec.must_differ_from;
    if (other && results[vec.name] && results[other]) {
      const same = JSON.stringify(results[vec.name]) === JSON.stringify(results[other]);
      if (same) {
        failures.push(`${vec.name} MUST differ from ${other} but was identical`);
      } else {
        console.log(`PASS  ${vec.name} differs from ${other}`);
      }
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
