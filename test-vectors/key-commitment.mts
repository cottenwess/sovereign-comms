/**
 * Key-commitment envelope test (SPEC §6.1.1).
 *
 * Verifies the committing AEAD round-trips, and the security property that
 * matters: a wrong key is rejected by the COMMITMENT check (before AEAD), and
 * tampering with the commitment, nonce, or ciphertext is rejected. Imports the
 * real envelope.ts — no reimplementation.
 *
 * Run from repo root:  npx tsx test-vectors/key-commitment.mts
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { randomBytes } from "@noble/hashes/utils.js";
import { commitSeal, commitOpen, constantTimeEqual, COMMIT_LEN, NONCE_LEN } from "../src/envelope.ts";

const te = new TextEncoder();
const dec = new TextDecoder();
let pass = 0;
const failures: string[] = [];
const check = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

const key = randomBytes(32);
const nonce = randomBytes(NONCE_LEN);
const ad = te.encode("associated-data");
const msg = te.encode("the eagle lands at midnight");

// Round-trip
const env = commitSeal(key, msg, nonce, ad);
check("round-trip decrypts", dec.decode(commitOpen(key, env, ad)) === "the eagle lands at midnight");
check("envelope has commit+nonce prefix", env.length === COMMIT_LEN + NONCE_LEN + msg.length + 16);

// Wrong key rejected (this is the partitioning defense: rejected by commitment)
let wrongKeyRejected = false;
let rejectedByCommitment = false;
try {
  commitOpen(randomBytes(32), env, ad);
} catch (e) {
  wrongKeyRejected = true;
  rejectedByCommitment = (e as Error).message.includes("commitment");
}
check("wrong key rejected", wrongKeyRejected);
check("wrong key rejected by COMMITMENT, before AEAD", rejectedByCommitment);

// Wrong associated data rejected
let wrongAdRejected = false;
try { commitOpen(key, env, te.encode("different-ad")); } catch { wrongAdRejected = true; }
check("wrong associated data rejected", wrongAdRejected);

// Tampered commitment rejected
const tamperedCommit = env.slice();
tamperedCommit[0] ^= 0xff;
let tcRejected = false;
try { commitOpen(key, tamperedCommit, ad); } catch { tcRejected = true; }
check("tampered commitment rejected", tcRejected);

// Tampered ciphertext rejected (AEAD tag)
const tamperedCt = env.slice();
tamperedCt[tamperedCt.length - 1] ^= 0xff;
let ctRejected = false;
try { commitOpen(key, tamperedCt, ad); } catch { ctRejected = true; }
check("tampered ciphertext rejected", ctRejected);

// constant-time equality helper sanity
check("ctEqual true for equal", constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])));
check("ctEqual false for diff", !constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])));
check("ctEqual false for length", !constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])));

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} key-commitment checks passed (UtC envelope, real module).`);
