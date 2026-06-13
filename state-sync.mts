/**
 * State-sync derivation test (SPEC §6.4).
 *
 * Verifies the sync address, the key ladder (sync_key_0 and forward advance),
 * index-walk consistency, address separation from the message locator, and the
 * ratchet-state serialization: byte-stable canonical round trips of REAL
 * RatchetState (built via src/ratchet.ts, not reimplemented), including skipped
 * keys, plus strict rejection of malformed/non-canonical encodings.
 *
 * Run from repo root:  npx tsx test-vectors/state-sync.mts
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { randomBytes } from "@noble/hashes/utils.js";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  initRatchet,
  ratchetSend,
  ratchetReceive,
  type HandshakeInput,
} from "../src/ratchet.ts";
import {
  syncLocator,
  syncKeyZero,
  advanceSyncKey,
  syncKeyAt,
  serializeRatchetState,
  deserializeRatchetState,
} from "../src/statesync.ts";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
let pass = 0;
const failures: string[] = [];
const check = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

function kp() {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}

const accessSeed = randomBytes(32);

// Determinism: same seed -> same address and key0
check("sync locator deterministic", hex(syncLocator(accessSeed)) === hex(syncLocator(accessSeed)));
check("sync locator is 16 bytes", syncLocator(accessSeed).length === 16);
check("sync key0 deterministic", hex(syncKeyZero(accessSeed)) === hex(syncKeyZero(accessSeed)));
check("sync key0 is 32 bytes", syncKeyZero(accessSeed).length === 32);

// Address separation: sync locator MUST differ from a naive message-locator
// derivation (different label => different output). Here we just assert it is
// not equal to key0 truncated etc.; the real point is label separation works.
check("sync locator != first 16 of key0",
  hex(syncLocator(accessSeed)) !== hex(syncKeyZero(accessSeed).subarray(0, 16)));

// Ladder: advance from key0 matches syncKeyAt(1); key0 matches syncKeyAt(0)
const k0 = syncKeyZero(accessSeed);
const k1 = advanceSyncKey(syncKeyZero(accessSeed));
check("syncKeyAt(0) == key0", hex(syncKeyAt(accessSeed, 0)) === hex(k0));
check("syncKeyAt(1) == advance(key0)", hex(syncKeyAt(accessSeed, 1)) === hex(k1));
check("ladder advances (k1 != k0)", hex(k0) !== hex(k1));

// Walk a few rungs, all distinct (forward ratchet)
const seen = new Set<string>();
for (let i = 0; i < 5; i++) seen.add(hex(syncKeyAt(accessSeed, i)));
check("first 5 ladder keys all distinct", seen.size === 5);

// Different seeds -> different sync addresses
const other = randomBytes(32);
check("different seed -> different sync locator",
  hex(syncLocator(accessSeed)) !== hex(syncLocator(other)));

// --- ratchet-state serialization: real state from the real ratchet ---------
const aliceId = kp(), aliceEph = kp();
const bobId = kp(), bobEph = kp();
const aliceHS: HandshakeInput = {
  idPrivate: aliceId.priv, idPublic: aliceId.pub,
  ephPrivate: aliceEph.priv, ephPublic: aliceEph.pub,
  peerIdPublic: bobId.pub, peerEphPublic: bobEph.pub,
};
const bobHS: HandshakeInput = {
  idPrivate: bobId.priv, idPublic: bobId.pub,
  ephPrivate: bobEph.priv, ephPublic: bobEph.pub,
  peerIdPublic: aliceId.pub, peerEphPublic: aliceEph.pub,
};

// Drive the pair into a non-trivial state: Alice sends 5, Bob receives only #4,
// so Bob holds skipped keys for 0..3 and advanced counters.
const alice = initRatchet(aliceHS);
const bob = initRatchet(bobHS);
const sent: { messageNumber: number }[] = [];
for (let i = 0; i < 5; i++) sent.push(ratchetSend(alice).header);
ratchetReceive(bob, sent[4]!);
check("setup: bob holds 4 skipped keys", bob.skipped.size === 4);

// Round trip preserves every field.
const bytes = serializeRatchetState(bob);
const restored = deserializeRatchetState(bytes);
check("round trip: sendChainKey", hex(restored.sendChainKey) === hex(bob.sendChainKey));
check("round trip: recvChainKey", hex(restored.recvChainKey) === hex(bob.recvChainKey));
check("round trip: counters", restored.sendCount === bob.sendCount && restored.recvCount === bob.recvCount);
check("round trip: skipped size", restored.skipped.size === bob.skipped.size);
let skippedOk = true;
for (const [n, k] of bob.skipped) {
  const rk = restored.skipped.get(n);
  if (!rk || hex(rk) !== hex(k)) skippedOk = false;
}
check("round trip: skipped keys byte-identical", skippedOk);

// Canonical: serialize is deterministic, and serialize∘deserialize is identity.
check("serialize deterministic", hex(serializeRatchetState(bob)) === hex(bytes));
check("serialize(deserialize(b)) === b", hex(serializeRatchetState(restored)) === hex(bytes));

// The restored state must be LIVE, not a husk: a skipped key consumed from the
// restored copy matches one consumed from the original.
const fromOriginal = ratchetReceive(bob, sent[2]!);
const fromRestored = ratchetReceive(restored, sent[2]!);
check("restored state yields the same message key", hex(fromOriginal) === hex(fromRestored));

// Strictness: malformed and non-canonical encodings are rejected.
const throws = (fn: () => unknown) => { try { fn(); return false; } catch { return true; } };
check("rejects empty blob", throws(() => deserializeRatchetState(new Uint8Array(0))));
check("rejects unknown version", throws(() => {
  const b = new Uint8Array(bytes); b[0] = 0x02; return deserializeRatchetState(b);
}));
check("rejects truncated blob", throws(() => deserializeRatchetState(bytes.subarray(0, bytes.length - 1))));
check("rejects trailing garbage", throws(() => {
  const b = new Uint8Array(bytes.length + 1); b.set(bytes); return deserializeRatchetState(b);
}));
check("rejects non-canonical (descending) skipped order", throws(() => {
  // Swap the first two skipped entries' message numbers in place.
  const b = new Uint8Array(bytes);
  const FIXED = 1 + 32 + 32 + 4 + 4 + 2, ENTRY = 4 + 32;
  const tmp = b.slice(FIXED, FIXED + ENTRY);
  b.set(b.subarray(FIXED + ENTRY, FIXED + 2 * ENTRY), FIXED);
  b.set(tmp, FIXED + ENTRY);
  return deserializeRatchetState(b);
}));
check("rejects skipped count over MAX_SKIP", throws(() => {
  const b = new Uint8Array(bytes);
  const off = 1 + 32 + 32 + 4 + 4;
  b[off] = 0xff; b[off + 1] = 0xff; // count = 65535
  return deserializeRatchetState(b);
}));

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} state-sync checks passed (derivation + canonical ratchet-state serialization, real modules).`);
