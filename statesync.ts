/**
 * GhostBox Protocol — Asynchronous state synchronization (SPEC §6.4)
 *
 * STATUS: IMPLEMENTED (v0.4.0). The deterministic derivation — the dedicated
 * sync address and the forward-ratcheted sync-key ladder — was implemented at
 * v0.3.x. The ratchet-state serialization it carries is now implemented too:
 * serializeRatchetState / deserializeRatchetState below encode the REAL
 * RatchetState from src/ratchet.ts (imported, not redefined) in a canonical,
 * byte-stable wire format suitable for the committing envelope.
 *
 * THE PROBLEM (SPEC §6.4)
 *   The Double Ratchet is stateful: decryption needs the root key, chain keys,
 *   counters, the live ephemeral DH private half, and skipped-message keys.
 *   Wipe-on-exit (SPEC §6.3) destroys all of it, so a returning user re-derives
 *   their identity but cannot decrypt anything sent since the last session.
 *
 * THE RESOLUTION (the part this module implements)
 *   Delegate ENCRYPTED ratchet state to the network, keeping the server passive.
 *   State lives at a dedicated derived address, distinct from the message
 *   Locator Hash, so the public address reveals neither that a state blob exists
 *   nor when it changes:
 *
 *     sync_locator = HKDF(access_seed, "ghostbox/v1/sync-locator", L=16)
 *     sync_key_0   = HKDF(access_seed, "ghostbox/v1/state-sync",   L=32)   // first
 *     sync_key_n   = HKDF(sync_key_{n-1}, "ghostbox/v1/state-sync", L=32)  // advance
 *
 *   The backup key is ratcheted forward once per sync and the prior key
 *   forgotten, so a leaked session key cannot decrypt other sessions' state.
 *   The encrypted state rides the committing envelope (envelope.ts), and on
 *   entry the client MUST drain and restore sync_locator BEFORE polling any
 *   message address, walking sync_key forward from index 0 until a blob
 *   decrypts. This restores forward secrecy for the BACKUP channel; it does not
 *   grant post-compromise security against capture of the live Quad-Key, which
 *   is permanent by design (SPEC §3) — an identity-layer concern, not a sync one.
 *
 * SCOPE NOTE (honesty)
 *   The ratchet this serializes is the SYMMETRIC ratchet of src/ratchet.ts
 *   (per-direction KDF chains; no per-message DH step) — see that module's
 *   header for why that matches the threat model. The serialized state contains
 *   raw chain keys and skipped message keys; it MUST only ever travel inside
 *   the committing envelope under a sync-ladder key (SPEC §6.4), never in the
 *   clear. Serialization format (version 0x01, all integers big-endian):
 *
 *     0x01 | sendChainKey(32) | recvChainKey(32) | sendCount(u32)
 *          | recvCount(u32) | skippedCount(u16)
 *          | skippedCount × ( messageNumber(u32) | messageKey(32) )
 *
 *   Skipped entries are sorted strictly ascending by message number, and
 *   deserialization REJECTS non-canonical encodings, so the mapping between
 *   state and bytes is one-to-one (byte-stable round trips).
 *
 *   npm install @noble/hashes
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const te = new TextEncoder();
const SYNC_LOCATOR_LABEL = te.encode("ghostbox/v1/sync-locator");
const STATE_SYNC_LABEL = te.encode("ghostbox/v1/state-sync");

/**
 * Derive the dedicated sync address from the access seed (SPEC §6.4). Distinct
 * from the message Locator Hash so the two are unlinkable at the address level.
 * 16 bytes, matching the Locator Hash width.
 */
export function syncLocator(accessSeed: Uint8Array): Uint8Array {
  return hkdf(sha256, accessSeed, undefined, SYNC_LOCATOR_LABEL, 16);
}

/** The first sync key: sync_key_0 = HKDF(access_seed, "...state-sync", 32). */
export function syncKeyZero(accessSeed: Uint8Array): Uint8Array {
  return hkdf(sha256, accessSeed, undefined, STATE_SYNC_LABEL, 32);
}

/** Advance the ladder: sync_key_n = HKDF(sync_key_{n-1}, "...state-sync", 32).
 *  Forgetting the prior key is the caller's responsibility (best-effort wipe). */
export function advanceSyncKey(prev: Uint8Array): Uint8Array {
  return hkdf(sha256, prev, undefined, STATE_SYNC_LABEL, 32);
}

/** Compute sync_key_n directly by walking the ladder from 0. Convenience for
 *  the restore path, which tries successive indices until a blob decrypts. */
export function syncKeyAt(accessSeed: Uint8Array, index: number): Uint8Array {
  if (index < 0 || !Number.isInteger(index)) {
    throw new Error("sync key index must be a non-negative integer");
  }
  let k = syncKeyZero(accessSeed);
  for (let i = 0; i < index; i++) {
    const next = advanceSyncKey(k);
    k.fill(0);
    k = next;
  }
  return k;
}

// ---------------------------------------------------------------------------
//  Ratchet state serialization — canonical wire format (SPEC §6.4)
// ---------------------------------------------------------------------------

import { MAX_SKIP, type RatchetState } from "./ratchet.js";

/** Re-exported so sync-channel callers need not import ratchet.ts separately. */
export type { RatchetState } from "./ratchet.js";

const STATE_VERSION = 0x01;
const KEY_LEN = 32;
const FIXED_LEN = 1 + KEY_LEN + KEY_LEN + 4 + 4 + 2; // version..skippedCount
const ENTRY_LEN = 4 + KEY_LEN;

function writeU32(out: Uint8Array, off: number, n: number): void {
  out[off] = (n >>> 24) & 0xff;
  out[off + 1] = (n >>> 16) & 0xff;
  out[off + 2] = (n >>> 8) & 0xff;
  out[off + 3] = n & 0xff;
}

function readU32(b: Uint8Array, off: number): number {
  return ((b[off]! << 24) | (b[off + 1]! << 16) | (b[off + 2]! << 8) | b[off + 3]!) >>> 0;
}

function assertU32(n: number, what: string): void {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`${what} out of u32 range: ${n}`);
  }
}

/**
 * Encode a live RatchetState into the canonical byte form. The output contains
 * raw key material: wrap it in the committing envelope under a sync-ladder key
 * before it leaves the process (SPEC §6.4), and best-effort wipe it after.
 */
export function serializeRatchetState(state: RatchetState): Uint8Array {
  if (state.sendChainKey.length !== KEY_LEN || state.recvChainKey.length !== KEY_LEN) {
    throw new Error(`chain keys must be ${KEY_LEN} bytes`);
  }
  assertU32(state.sendCount, "sendCount");
  assertU32(state.recvCount, "recvCount");
  if (state.skipped.size > MAX_SKIP) {
    throw new Error(`skipped-key count ${state.skipped.size} exceeds MAX_SKIP (${MAX_SKIP})`);
  }

  const entries = [...state.skipped.entries()].sort((a, b) => a[0] - b[0]);
  const out = new Uint8Array(FIXED_LEN + entries.length * ENTRY_LEN);

  out[0] = STATE_VERSION;
  out.set(state.sendChainKey, 1);
  out.set(state.recvChainKey, 1 + KEY_LEN);
  writeU32(out, 1 + 2 * KEY_LEN, state.sendCount);
  writeU32(out, 1 + 2 * KEY_LEN + 4, state.recvCount);
  out[1 + 2 * KEY_LEN + 8] = (entries.length >>> 8) & 0xff;
  out[1 + 2 * KEY_LEN + 9] = entries.length & 0xff;

  let off = FIXED_LEN;
  for (const [num, key] of entries) {
    assertU32(num, "skipped message number");
    if (key.length !== KEY_LEN) throw new Error(`skipped key must be ${KEY_LEN} bytes`);
    writeU32(out, off, num);
    out.set(key, off + 4);
    off += ENTRY_LEN;
  }
  return out;
}

/**
 * Decode the canonical byte form back into a RatchetState. Strict by design:
 * rejects unknown versions, wrong lengths, over-cap skipped counts, and
 * non-canonical (unsorted / duplicate) skipped entries, so every accepted byte
 * string has exactly one serialization (serialize(deserialize(b)) === b).
 */
export function deserializeRatchetState(bytes: Uint8Array): RatchetState {
  if (bytes.length < FIXED_LEN) throw new Error("ratchet state blob too short");
  if (bytes[0] !== STATE_VERSION) {
    throw new Error(`unknown ratchet state version 0x${bytes[0]!.toString(16)}`);
  }

  const skippedCount = ((bytes[1 + 2 * KEY_LEN + 8]! << 8) | bytes[1 + 2 * KEY_LEN + 9]!) >>> 0;
  if (skippedCount > MAX_SKIP) {
    throw new Error(`skipped-key count ${skippedCount} exceeds MAX_SKIP (${MAX_SKIP})`);
  }
  const expected = FIXED_LEN + skippedCount * ENTRY_LEN;
  if (bytes.length !== expected) {
    throw new Error(`ratchet state blob length ${bytes.length}, expected ${expected}`);
  }

  const skipped = new Map<number, Uint8Array>();
  let off = FIXED_LEN;
  let prev = -1;
  for (let i = 0; i < skippedCount; i++) {
    const num = readU32(bytes, off);
    if (num <= prev) {
      throw new Error("non-canonical ratchet state: skipped entries must be strictly ascending");
    }
    prev = num;
    skipped.set(num, bytes.slice(off + 4, off + 4 + KEY_LEN));
    off += ENTRY_LEN;
  }

  return {
    sendChainKey: bytes.slice(1, 1 + KEY_LEN),
    recvChainKey: bytes.slice(1 + KEY_LEN, 1 + 2 * KEY_LEN),
    sendCount: readU32(bytes, 1 + 2 * KEY_LEN),
    recvCount: readU32(bytes, 1 + 2 * KEY_LEN + 4),
    skipped,
  };
}
