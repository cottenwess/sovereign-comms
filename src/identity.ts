/**
 * GhostBox Protocol — Spirit Layer reference implementation
 * Identity derivation: Quad-Key -> Locator Hash (public) + Access Token seed (private)
 *
 * CANONICAL reference. See SPECIFICATION.md §3 (Spirit Layer).
 *
 * This file is a READABLE reference, not a hardened library. It demonstrates the
 * correct construction. Before production use, review SPECIFICATION.md §8 (threat
 * model) and have the implementation independently audited.
 *
 * Divergences from the book's illustrative Python (deliberate — see SPEC §0.4):
 *   - Per-composite salts via HKDF (not static salts).
 *   - Variable factor composite (not a fixed 4 words).
 *   - Keypairs derived from the Access Token seed.
 *
 * Dependency note: Argon2id is NOT native to browsers/Node. This reference uses
 * `hash-wasm` (a WASM build). Do NOT substitute a pure-JS Argon2 — it cannot run
 * safe parameters at acceptable speed and silently weakens every identity.
 *
 *   npm install hash-wasm @noble/curves @noble/hashes
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { argon2id } from "hash-wasm";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { ed25519, x25519 } from "@noble/curves/ed25519";

// --- Parameter ladder (SPEC §3.4) -----------------------------------------
// Versioned so cost can rise over time without orphaning existing identities.
// The version is published in the alias record so a recipient knows which rung
// to derive against.

export interface ArgonParams {
  readonly version: string;
  readonly memorySizeKiB: number; // hash-wasm uses KiB
  readonly iterations: number;
  readonly parallelism: number;
}

export const ARGON_PARAMS: Record<string, ArgonParams> = {
  "argon2id-v1": {
    version: "argon2id-v1",
    memorySizeKiB: 65536, // 64 MiB
    iterations: 4,
    parallelism: 4,
  },
  "argon2id-v2": {
    version: "argon2id-v2",
    memorySizeKiB: 262144, // 256 MiB
    iterations: 4,
    parallelism: 4,
  },
};

// --- Entropy floor (SPEC §3.2) --------------------------------------------
// The composite MUST reach at least 128 bits of estimated entropy before
// derivation proceeds. This is a coarse gate; real onboarding UX should use a
// proper estimator (e.g. zxcvbn) per knowledge-factor and a fixed allowance for
// high-entropy factors (hardware tokens, biometric hashes, SSI credentials).

export const MIN_ENTROPY_BITS = 128;

const UNIT_SEP = 0x1f; // factor separator; cannot appear in NFC text or hashes

export type FactorClass = "know" | "are" | "have" | "who";

export interface Factor {
  readonly class: FactorClass;
  /**
   * Bytes for this factor.
   *   - "know": NFC-normalized UTF-8 of the secret text
   *   - "are" / "have" / "who": the fixed-length HASH of the factor,
   *     never the raw biometric / document / contact data
   */
  readonly bytes: Uint8Array;
  /** Estimated entropy contribution in bits (caller supplies; see note above). */
  readonly entropyBits: number;
}

/** NFC-normalize text and return UTF-8 bytes. Use for "know" factors. */
export function textFactor(secret: string, entropyBits: number): Factor {
  const normalized = secret.normalize("NFC");
  return {
    class: "know",
    bytes: new TextEncoder().encode(normalized),
    entropyBits,
  };
}

/**
 * Canonicalize factors into the composite (SPEC §3.6).
 * Order is user-fixed and is PART OF THE SECRET — do not sort.
 */
export function canonicalize(factors: readonly Factor[]): Uint8Array {
  if (factors.length < 4) {
    throw new Error("Quad-Key requires at least 4 factors (SPEC §3.2).");
  }
  const total = factors.reduce((n, f) => n + f.bytes.length, 0);
  const out = new Uint8Array(total + (factors.length - 1));
  let pos = 0;
  factors.forEach((f, i) => {
    out.set(f.bytes, pos);
    pos += f.bytes.length;
    if (i < factors.length - 1) out[pos++] = UNIT_SEP;
  });
  return out;
}

/** Enforce the entropy floor (SPEC §3.2). Throws if below MIN_ENTROPY_BITS. */
export function assertEntropyFloor(factors: readonly Factor[]): void {
  const bits = factors.reduce((n, f) => n + f.entropyBits, 0);
  if (bits < MIN_ENTROPY_BITS) {
    throw new Error(
      `Composite entropy ${bits} bits < required ${MIN_ENTROPY_BITS} (SPEC §3.2).`,
    );
  }
}

/** HKDF-Extract (SHA-256) producing a 32-byte per-composite salt (SPEC §3.3). */
function hkdfSalt(composite: Uint8Array, label: string): Uint8Array {
  // domain separation via the `info` parameter; salt param is the composite
  return hkdf(sha256, composite, undefined, new TextEncoder().encode(label), 32);
}

async function argon(
  composite: Uint8Array,
  salt: Uint8Array,
  lengthBytes: number,
  p: ArgonParams,
): Promise<Uint8Array> {
  const hex = await argon2id({
    password: composite,
    salt,
    parallelism: p.parallelism,
    iterations: p.iterations,
    memorySize: p.memorySizeKiB,
    hashLength: lengthBytes,
    outputType: "binary",
  });
  return hex as unknown as Uint8Array;
}

export interface Identity {
  /** PUBLIC. The Drop-Box address others deposit to. Deposit-only. */
  readonly locatorHash: Uint8Array; // 16 bytes
  /** PRIVATE. Seeds signing + encryption keys. RAM only — never persist/transmit. */
  readonly accessSeed: Uint8Array; // 32 bytes
  /** PRIVATE. Ed25519 signing key for retrieval challenge-response (SPEC §4.3). */
  readonly signingPrivate: Uint8Array;
  /** PUBLIC. Ed25519 verify key registered against the Locator Hash. */
  readonly signingPublic: Uint8Array;
  /** PRIVATE. X25519 key for message decryption (SPEC §6). */
  readonly encryptionPrivate: Uint8Array;
  /** PUBLIC. X25519 key others encrypt to. */
  readonly encryptionPublic: Uint8Array;
  readonly paramVersion: string;
}

/**
 * Derive a full GhostBox identity from a composite Quad-Key.
 *
 * @param factors  ordered factors (order is secret)
 * @param paramVersion  which Argon2id ladder rung (default newest sane: v1)
 *
 * SECURITY: the returned private material lives only as long as you keep it.
 * Zero it when the session ends; never write it to disk or send it anywhere.
 */
export async function deriveIdentity(
  factors: readonly Factor[],
  paramVersion: keyof typeof ARGON_PARAMS = "argon2id-v1",
): Promise<Identity> {
  assertEntropyFloor(factors);
  const params = ARGON_PARAMS[paramVersion];
  const composite = canonicalize(factors);

  const saltLocator = hkdfSalt(composite, "ghostbox/v1/locator");
  const saltAccess = hkdfSalt(composite, "ghostbox/v1/access");

  const locatorHash = await argon(composite, saltLocator, 16, params);
  const accessSeed = await argon(composite, saltAccess, 32, params);

  // Derive keypairs from the access seed via domain-separated HKDF so the two
  // keypairs are independent and neither equals the raw seed.
  const signSeed = hkdf(sha256, accessSeed, undefined, "ghostbox/v1/sign", 32);
  const encSeed = hkdf(sha256, accessSeed, undefined, "ghostbox/v1/enc", 32);

  const signingPublic = ed25519.getPublicKey(signSeed);
  const encryptionPublic = x25519.getPublicKey(encSeed);

  // best-effort wipe of the composite
  composite.fill(0);

  return {
    locatorHash,
    accessSeed,
    signingPrivate: signSeed,
    signingPublic,
    encryptionPrivate: encSeed,
    encryptionPublic,
    paramVersion,
  };
}

/** Hex helper for display / addressing. */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
