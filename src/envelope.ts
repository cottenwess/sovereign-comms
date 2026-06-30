/**
 * GhostBox Protocol — Committing AEAD envelope (Specter Layer crypto)
 * The canonical message envelope for every Specter-layer PUT (SPEC §6.1.1).
 *
 * WHY THIS EXISTS
 *   XChaCha20-Poly1305 (and AES-GCM) provide confidentiality and integrity but
 *   NOT key commitment: an attacker who controls key material can craft a single
 *   ciphertext that decrypts validly under two different keys to two different
 *   plaintexts. This is the Invisible Salamanders / partitioning-oracle attack.
 *   It bites the Mediated Introduction discovery mode (SPEC §5), where one party
 *   hands a payload intended to be opened by two recipients. Every AEAD
 *   operation is therefore wrapped in a committing transform.
 *
 * THE CONSTRUCTION — UtC (UNAE-then-Commit), Bellare–Hoang
 *   Gives CMT-4 commitment over key, nonce, and associated data:
 *
 *     subkey = HKDF(K, info="ghostbox/v1/aead-subkey" || N,          L=32)
 *     commit = HKDF(K, info="ghostbox/v1/key-commit"  || N || H(AD), L=32)
 *     (ct, tag) = AEAD-Encrypt(key=subkey, nonce=N, plaintext=P, ad=AD)
 *     envelope  = commit || N || ct||tag
 *
 *   The AEAD is keyed by `subkey`, never by K directly. On receipt the client
 *   MUST recompute `commit` from its own key, compare in CONSTANT TIME, and
 *   REJECT before AEAD decryption on mismatch. Cost: one extra HKDF call and 32
 *   bytes per message.
 *
 * SCOPE / HONESTY
 *   This commits the AEAD layer. It is not, by itself, forward secrecy (that is
 *   the Double Ratchet, SPEC §6.2 / §6.4). It defends a specific, real attack on
 *   the AEAD primitive; it does not turn the reference into a hardened or
 *   audited library.
 *
 *   npm install @noble/ciphers @noble/hashes
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

const COMMIT_LEN = 32;
const NONCE_LEN = 24; // XChaCha20-Poly1305 nonce
const te = new TextEncoder();

/** Concatenate byte arrays. */
function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

/** Constant-time equality for two equal-length byte arrays. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

const SUBKEY_LABEL = te.encode("ghostbox/v1/aead-subkey");
const COMMIT_LABEL = te.encode("ghostbox/v1/key-commit");

/** subkey = HKDF(K, info="ghostbox/v1/aead-subkey" || N, L=32) */
function deriveSubkey(key: Uint8Array, nonce: Uint8Array): Uint8Array {
  return hkdf(sha256, key, undefined, concat(SUBKEY_LABEL, nonce), 32);
}

/** commit = HKDF(K, info="ghostbox/v1/key-commit" || N || H(AD), L=32) */
function deriveCommit(key: Uint8Array, nonce: Uint8Array, ad: Uint8Array): Uint8Array {
  const hAd = sha256(ad);
  return hkdf(sha256, key, undefined, concat(COMMIT_LABEL, nonce, hAd), COMMIT_LEN);
}

/**
 * Wrap a plaintext in the committing envelope.
 *
 * @param key        the message key K (e.g. a sealed-box shared secret, or a
 *                   Double Ratchet message key once §6.4 lands)
 * @param plaintext  bytes to encrypt
 * @param nonce      24-byte XChaCha nonce (caller supplies; MUST be unique per key)
 * @param ad         associated data, authenticated and bound into the commitment
 * @returns envelope = commit(32) || nonce(24) || aead_ciphertext
 */
export function commitSeal(
  key: Uint8Array,
  plaintext: Uint8Array,
  nonce: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (nonce.length !== NONCE_LEN) {
    throw new Error(`nonce must be ${NONCE_LEN} bytes`);
  }
  const subkey = deriveSubkey(key, nonce);
  const commit = deriveCommit(key, nonce, ad);
  const ct = xchacha20poly1305(subkey, nonce, ad).encrypt(plaintext);
  subkey.fill(0);
  return concat(commit, nonce, ct);
}

/**
 * Open a committing envelope. Recomputes the commitment from the caller's key
 * and REJECTS in constant time before AEAD decryption on mismatch — the whole
 * point of the construction.
 *
 * @throws if the commitment does not match (wrong key / partitioning attempt) or
 *         the AEAD tag fails.
 */
export function commitOpen(
  key: Uint8Array,
  envelope: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (envelope.length < COMMIT_LEN + NONCE_LEN) {
    throw new Error("envelope too short");
  }
  const commit = envelope.subarray(0, COMMIT_LEN);
  const nonce = envelope.subarray(COMMIT_LEN, COMMIT_LEN + NONCE_LEN);
  const ct = envelope.subarray(COMMIT_LEN + NONCE_LEN);

  // Recompute the commitment and reject BEFORE touching the AEAD.
  const expected = deriveCommit(key, nonce, ad);
  if (!constantTimeEqual(commit, expected)) {
    throw new Error("key commitment mismatch: envelope rejected before decryption");
  }
  const subkey = deriveSubkey(key, nonce);
  const pt = xchacha20poly1305(subkey, nonce, ad).decrypt(ct);
  subkey.fill(0);
  return pt;
}

export { COMMIT_LEN, NONCE_LEN };
