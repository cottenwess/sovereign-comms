/**
 * GhostBox Protocol — Symmetric-key ratchet (Specter Layer, SPEC §6.2)
 *
 * STATUS: core + tests, and WIRED (v0.4.0): transport.ts routes these message
 * keys through the committing envelope on the RatchetSession path, and
 * statesync.ts serializes RatchetState for the §6.4 sync channel. This module
 * remains standalone and reviewable in isolation.
 *
 * WHAT IT IS
 *   A symmetric-key ratchet giving FORWARD SECRECY: one KDF chain per direction
 *   per pair. Each message advances its chain and the prior chain key is
 *   forgotten, so a leaked chain key cannot derive EARLIER message keys.
 *
 * WHAT IT IS NOT (deliberate, matches the threat model)
 *   - NOT a DH ratchet. There is no per-message DH step and therefore NO
 *     post-compromise (self-healing) security at the session level. This is by
 *     design: the Quad-Key / identity compromise is permanent (SPEC §3, §6.4),
 *     so session-level PCS would heal a wound the identity layer leaves open
 *     anyway. Forward secrecy is the property §6.2 actually requires; this
 *     provides exactly that and says so.
 *   - NOT audited. Reference for review, not deployment.
 *
 * CONSTRUCTION
 *   Handshake (triple-DH), at Corporeal Layer connection (SPEC §5.3). Each side
 *   contributes a fresh ephemeral X25519 key alongside its identity X25519 key:
 *
 *     root = HKDF( DH(id_self, eph_peer) || DH(eph_self, id_peer)
 *                                        || DH(eph_self, eph_peer),
 *                  info="ghostbox/v1/root", L=32 )
 *
 *   The triple-DH binds the session to both parties' identities AND to fresh
 *   ephemerals, so session secrecy does not rest solely on long-term keys. To
 *   make the two directions agree without a live round trip, the DH terms are
 *   ordered canonically by the two identity public keys (lower key first), so
 *   both peers compute the SAME root regardless of who is "A".
 *
 *   Per-direction chains seed from the root with a role label:
 *     send_chain_0 = HKDF(root, "chain/" + myRole,   L=32)
 *     recv_chain_0 = HKDF(root, "chain/" + peerRole, L=32)
 *   where roles are "lo"/"hi" by the canonical key ordering (the lower-keyed
 *   party is "lo"). One party's send chain is the other's receive chain.
 *
 *   Symmetric ratchet step:
 *     message_key_n = HKDF(chain_key_n, "msg",   L=32)
 *     chain_key_n+1 = HKDF(chain_key_n, "chain", L=32)   // old key forgotten
 *
 *   Out-of-order / batched delivery (a dead-drop drains many blobs at once):
 *   the receiver advances its chain to the message number, storing skipped
 *   message keys along the way, up to MAX_SKIP (64) per chain. Exceeding the cap
 *   throws RatchetSkipLimitError, signalling a required re-handshake rather than
 *   unbounded growth.
 *
 *   npm install @noble/curves @noble/hashes
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const te = new TextEncoder();
const L = 32;

/** Hard cap on stored skipped message keys per chain (locked design value). */
export const MAX_SKIP = 64;

export class RatchetSkipLimitError extends Error {
  constructor(limit: number) {
    super(
      `skipped-message-key limit (${limit}) exceeded for this chain; re-handshake required`,
    );
    this.name = "RatchetSkipLimitError";
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const n = parts.reduce((a, p) => a + p.length, 0);
  const out = new Uint8Array(n);
  let pos = 0;
  for (const p of parts) { out.set(p, pos); pos += p.length; }
  return out;
}

const hexByte = (b: Uint8Array) =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** Lexicographic compare of two equal-length byte arrays. <0 if a<b. */
function cmp(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < a.length; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return 0;
}

// ---------------------------------------------------------------------------
//  Handshake — triple-DH root, canonicalized so both peers agree
// ---------------------------------------------------------------------------

export interface HandshakeInput {
  /** This party's identity X25519 private key (from the Spirit Layer). */
  readonly idPrivate: Uint8Array;
  /** This party's identity X25519 public key. */
  readonly idPublic: Uint8Array;
  /** This party's fresh ephemeral X25519 private key (per handshake). */
  readonly ephPrivate: Uint8Array;
  /** This party's fresh ephemeral X25519 public key. */
  readonly ephPublic: Uint8Array;
  /** Peer's identity X25519 public key. */
  readonly peerIdPublic: Uint8Array;
  /** Peer's ephemeral X25519 public key (received during the handshake). */
  readonly peerEphPublic: Uint8Array;
}

const ROOT_INFO = te.encode("ghostbox/v1/root");

/**
 * Derive the shared session root from a triple-DH. The three DH terms are
 * ordered by the canonical identity-key ordering (lower identity key's terms
 * first) so both parties compute the identical root without a live round trip.
 */
export function deriveRoot(h: HandshakeInput): Uint8Array {
  // DH terms from THIS party's viewpoint.
  const dh_id_eph = x25519.getSharedSecret(h.idPrivate, h.peerEphPublic);   // DH(id_self, eph_peer)
  const dh_eph_id = x25519.getSharedSecret(h.ephPrivate, h.peerIdPublic);   // DH(eph_self, id_peer)
  const dh_eph_eph = x25519.getSharedSecret(h.ephPrivate, h.peerEphPublic); // DH(eph_self, eph_peer)

  // Canonical ordering: if THIS party's identity key is the lower one, our
  // (id_self·eph_peer) is the "lo·hi" term; else swap the first two so both
  // sides concatenate the same sequence. The eph·eph term is symmetric.
  const selfIsLo = cmp(h.idPublic, h.peerIdPublic) < 0;
  const ikm = selfIsLo
    ? concat(dh_id_eph, dh_eph_id, dh_eph_eph)
    : concat(dh_eph_id, dh_id_eph, dh_eph_eph);

  const root = hkdf(sha256, ikm, undefined, ROOT_INFO, L);
  dh_id_eph.fill(0); dh_eph_id.fill(0); dh_eph_eph.fill(0); ikm.fill(0);
  return root;
}

/** Which role this party plays, by canonical identity-key ordering. */
export function roleOf(idPublic: Uint8Array, peerIdPublic: Uint8Array): "lo" | "hi" {
  return cmp(idPublic, peerIdPublic) < 0 ? "lo" : "hi";
}

// ---------------------------------------------------------------------------
//  Chains
// ---------------------------------------------------------------------------

const CHAIN_STEP = te.encode("chain");
const MSG_STEP = te.encode("msg");

function chainSeed(root: Uint8Array, role: "lo" | "hi"): Uint8Array {
  return hkdf(sha256, root, undefined, te.encode("chain/" + role), L);
}

function stepChain(chainKey: Uint8Array): { messageKey: Uint8Array; next: Uint8Array } {
  const messageKey = hkdf(sha256, chainKey, undefined, MSG_STEP, L);
  const next = hkdf(sha256, chainKey, undefined, CHAIN_STEP, L);
  return { messageKey, next };
}

// ---------------------------------------------------------------------------
//  Ratchet session (one peer pair)
// ---------------------------------------------------------------------------

export interface RatchetState {
  readonly sendChainKey: Uint8Array;
  readonly recvChainKey: Uint8Array;
  /** Next message number this party will SEND. */
  sendCount: number;
  /** Next message number expected to RECEIVE in order. */
  recvCount: number;
  /** Skipped receive keys: "msgNumber" -> messageKey, capped at MAX_SKIP. */
  readonly skipped: Map<number, Uint8Array>;
}

/** Build the initial ratchet state for a pair from a completed handshake. */
export function initRatchet(h: HandshakeInput): RatchetState {
  const root = deriveRoot(h);
  const myRole = roleOf(h.idPublic, h.peerIdPublic);
  const peerRole = myRole === "lo" ? "hi" : "lo";
  const state: RatchetState = {
    sendChainKey: chainSeed(root, myRole),
    recvChainKey: chainSeed(root, peerRole),
    sendCount: 0,
    recvCount: 0,
    skipped: new Map(),
  };
  root.fill(0);
  return state;
}

export interface RatchetHeader {
  readonly messageNumber: number;
}

/** Encrypt-side step: produce the message key for the next outbound message and
 *  the header to authenticate alongside it (the header goes in the committing
 *  envelope's AD when this is wired into transport). */
export function ratchetSend(state: RatchetState): { messageKey: Uint8Array; header: RatchetHeader } {
  const { messageKey, next } = stepChain(state.sendChainKey);
  state.sendChainKey.set(next); // advance in place; old key overwritten
  next.fill(0);
  const header = { messageNumber: state.sendCount };
  state.sendCount += 1;
  return { messageKey, header };
}

/**
 * Decrypt-side step: return the message key for the inbound message identified
 * by its header, advancing the receive chain and storing skipped keys (up to
 * MAX_SKIP) for any gap. If the message number is older than recvCount, a
 * previously-skipped key is consumed.
 *
 * @throws RatchetSkipLimitError if the gap would exceed MAX_SKIP.
 * @throws Error if the message number was already consumed and not in skipped.
 */
export function ratchetReceive(state: RatchetState, header: RatchetHeader): Uint8Array {
  const n = header.messageNumber;

  if (n < state.recvCount) {
    const key = state.skipped.get(n);
    if (!key) throw new Error(`message ${n} already consumed or never skipped`);
    state.skipped.delete(n);
    return key;
  }

  const gap = n - state.recvCount;
  if (state.skipped.size + gap > MAX_SKIP) {
    throw new RatchetSkipLimitError(MAX_SKIP);
  }

  // Advance to n, storing skipped keys for [recvCount, n).
  let chainKey = state.recvChainKey;
  for (let i = state.recvCount; i < n; i++) {
    const { messageKey, next } = stepChain(chainKey);
    state.skipped.set(i, messageKey);
    chainKey = next;
  }
  // Derive the target message key and advance the chain past it.
  const { messageKey, next } = stepChain(chainKey);
  state.recvChainKey.set(next);
  next.fill(0);
  state.recvCount = n + 1;
  return messageKey;
}

/** Hex of a chain key, for tests/inspection only. Never log real keys. */
export function chainKeyHex(state: RatchetState, which: "send" | "recv"): string {
  return hexByte(which === "send" ? state.sendChainKey : state.recvChainKey);
}
