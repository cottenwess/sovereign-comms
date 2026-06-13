/**
 * Cross-language vector checker (TypeScript) — imports the REAL module.
 *
 * This file deliberately does NOT reimplement derivation. It calls the actual
 * src/identity.ts exports, so a divergence between the module and the frozen
 * vectors is caught here. (An earlier checker reimplemented the logic inline and
 * masked a real bug: the module used full HKDF while the inline copy used bare
 * HMAC, and CI stayed green while the two languages disagreed. Never again —
 * checkers import, they do not reimplement.)
 *
 * Run from repo root:  npx tsx test-vectors/verify_vectors.mts
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  deriveIdentity,
  textFactor,
  hashedFactor,
  toHex,
  type Factor,
  type FactorClass,
} from "../src/identity.ts";

const here = dirname(fileURLToPath(import.meta.url));
const data = JSON.parse(readFileSync(join(here, "identity.json"), "utf8"));
const te = new TextEncoder();

interface VecFactor {
  class: FactorClass;
  text?: string;
  sha256_of?: string;
  declared_bits?: number;
  provenance?: string;
}

function buildFactor(vf: VecFactor): Factor {
  if (vf.class === "know") {
    if (typeof vf.text !== "string") throw new Error("know factor needs text");
    return textFactor(vf.text);
  }
  if (typeof vf.sha256_of !== "string") throw new Error("hashed factor needs sha256_of");
  const digest = sha256(te.encode(vf.sha256_of));
  return hashedFactor(vf.class, digest, vf.declared_bits ?? 0, vf.provenance ?? "");
}

const seen = new Map<string, string>();
let pass = 0;
const failures: string[] = [];
const ok = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

for (const v of data.vectors) {
  const factors = (v.factors as VecFactor[]).map(buildFactor);
  if (v.expected.throws) {
    let threw = false;
    let msg = "";
    try {
      await deriveIdentity(factors, v.param_version);
    } catch (e) {
      threw = true;
      msg = (e as Error).message.toLowerCase();
    }
    ok(`${v.name} (must throw)`, threw && msg.includes((v.expected.error_contains ?? "").toLowerCase()));
    continue;
  }
  const id = await deriveIdentity(factors, v.param_version);
  const loc = toHex(id.locatorHash);
  ok(`${v.name} locator`, loc === v.expected.locator_hash_hex);
  ok(`${v.name} signing`, toHex(id.signingPublic) === v.expected.signing_public_hex);
  ok(`${v.name} encryption`, toHex(id.encryptionPublic) === v.expected.encryption_public_hex);
  if (v.must_differ_from) {
    const other = seen.get(v.must_differ_from);
    ok(`${v.name} differs from ${v.must_differ_from}`, other !== undefined && other !== loc);
  }
  seen.set(v.name, loc);
}

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} checks passed (TypeScript canonical, real module imported).`);
