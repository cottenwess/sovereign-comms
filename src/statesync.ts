/**
 * GhostBox Protocol — Asynchronous state synchronization (SPEC §6.4)
 *
 * STATUS: PARTIAL. The deterministic derivation below — the dedicated sync
 * address and the forward-ratcheted sync-key ladder — is implemented and
 * tested. The piece it serves, the Double Ratchet session state it would carry,
 * is NOT implemented here (see "NOT YET BUILT" below). This module is the
 * transport scaffolding for state sync; it is deliberately honest that the
 * payload it would carry does not yet exist.
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
 * NOT YET BUILT (requires design review before implementation)
 *   - The Double Ratchet itself (root/chain key evolution, DH ratchet steps,
 *     skipped-message-key handling). SPEC §6.2. Building a correct ratchet is
 *     audit-sensitive and intentionally deferred; this module provides the
 *     address + key ladder it will use, not the ratchet.
 *   - serializeRatchetState / deserializeRatchetState below are STUBS that throw.
 *     They define the boundary so callers compile against a stable surface, and
 *     fail loudly rather than silently shipping a fake ratchet.
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
//  Ratchet state serialization — STUBS. Defined surface, not yet implemented.
// ---------------------------------------------------------------------------

/** Placeholder for the Double Ratchet session state (SPEC §6.2). Shape TBD at
 *  ratchet implementation time; intentionally opaque here. */
export interface RatchetState {
  readonly __unimplemented: true;
}

export function serializeRatchetState(_state: RatchetState): Uint8Array {
  throw new Error(
    "serializeRatchetState: the Double Ratchet (SPEC §6.2) is not yet implemented. " +
      "The sync address and key ladder are ready; the ratchet they carry is pending design review.",
  );
}

export function deserializeRatchetState(_bytes: Uint8Array): RatchetState {
  throw new Error(
    "deserializeRatchetState: the Double Ratchet (SPEC §6.2) is not yet implemented. " +
      "See SPEC §6.4 and the NOT YET BUILT note in this module.",
  );
}
