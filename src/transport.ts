/**
 * GhostBox Protocol — Specter Layer reference implementation
 * The passive dead-drop transport that cannot link sender to recipient.
 *
 * CANONICAL reference. See SPECIFICATION.md §4 (Specter Layer).
 *
 * WHAT THIS DEMONSTRATES
 *   The protocol's own data structures do not encode the social graph. A server
 *   running this stores ciphertext at mailbox addresses (locator hashes) and,
 *   separately, releases it to whoever proves possession of the matching access
 *   key. It records no link between a deposit and the depositor, and no link
 *   between a deposit and a later drain. If the server's entire state were
 *   seized, it would reveal which mailboxes received traffic and which were
 *   drained — but NOT who sent to whom. See verify_unlinkability.mjs for a
 *   runnable proof-by-inspection of exactly that.
 *
 * WHAT THIS DOES NOT ESTABLISH (read this — the project's thesis is honesty)
 *   - NOT forward secrecy. This uses sealed-box encryption (ephemeral-static
 *     X25519 + XChaCha20-Poly1305), which gives SENDER ANONYMITY but not the
 *     forward secrecy the spec calls for (SPEC §6.2 Double Ratchet). Compromise
 *     of a recipient's long-term key exposes past messages. Documented gap.
 *   - NOT resistance to network-layer correlation. If the transport leaks IP or
 *     timing, an observer can correlate deposit and drain regardless of what the
 *     server stores. This is application-layer unlinkability only; the network
 *     layer needs Tor/a mixnet (SPEC §8.4). A reference implementation cannot
 *     solve this and does not claim to.
 *   - NOT a formal anonymity proof. Proof-by-inspection of server state is an
 *     existence argument, not a cryptographic proof against a global passive
 *     adversary. That belongs in a paper (PETS/ePrint), not a README.
 *   - NOT audited, NOT hardened. Reference for review, not deployment.
 *
 *   npm install @noble/ciphers @noble/curves @noble/hashes
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { x25519 } from "@noble/curves/ed25519";
import { ed25519 } from "@noble/curves/ed25519";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";

const toHexKey = (b: Uint8Array): string =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

// ===========================================================================
//  SEALED BOX — sender-anonymous authenticated encryption (SPEC §4.5, §6)
// ===========================================================================
//
// A fresh ephemeral keypair is generated PER MESSAGE. The shared secret is
// ECDH(ephemeral_priv, recipient_pub). Only the recipient can derive the same
// secret (ECDH(recipient_priv, ephemeral_pub)). Because the sender's key is
// ephemeral and thrown away, the ciphertext carries no stable sender identity —
// which is precisely the property the dead-drop needs: a deposit cannot be tied
// to a sender by its contents.
//
// Wire layout of a sealed blob:
//   [ ephemeral_pub (32) | nonce (24) | aead_ciphertext (..) ]

const EPH_LEN = 32;
const NONCE_LEN = 24;

function deriveBoxKey(shared: Uint8Array): Uint8Array {
  // Domain-separate the raw ECDH output before using it as an AEAD key.
  return hkdf(sha256, shared, undefined, "ghostbox/v1/sealedbox", 32);
}

/** Encrypt `message` to a recipient's X25519 public key. Sender is anonymous. */
export function seal(recipientX25519Pub: Uint8Array, message: Uint8Array): Uint8Array {
  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientX25519Pub);
  const key = deriveBoxKey(shared);
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce).encrypt(message);

  const out = new Uint8Array(EPH_LEN + NONCE_LEN + ct.length);
  out.set(ephPub, 0);
  out.set(nonce, EPH_LEN);
  out.set(ct, EPH_LEN + NONCE_LEN);
  // best-effort wipe of ephemeral private + shared secret
  ephPriv.fill(0);
  shared.fill(0);
  return out;
}

/** Decrypt a sealed blob using the recipient's X25519 private key. */
export function unseal(recipientX25519Priv: Uint8Array, blob: Uint8Array): Uint8Array {
  const ephPub = blob.subarray(0, EPH_LEN);
  const nonce = blob.subarray(EPH_LEN, EPH_LEN + NONCE_LEN);
  const ct = blob.subarray(EPH_LEN + NONCE_LEN);
  const shared = x25519.getSharedSecret(recipientX25519Priv, ephPub);
  const key = deriveBoxKey(shared);
  const pt = xchacha20poly1305(key, nonce).decrypt(ct);
  shared.fill(0);
  return pt;
}

// ===========================================================================
//  THE DROP SERVER — passive dead-drop (SPEC §4.1–§4.4)
// ===========================================================================
//
// Deliberately "dumb": it stores opaque blobs at locator addresses and releases
// them to whoever can sign a challenge with the access key bound to that
// locator. It is structurally unable to record a sender→recipient relationship,
// because deposits are UNAUTHENTICATED — anyone may deposit to any locator, and
// the server is given nothing that identifies the depositor.
//
// The internal state below is intentionally inspectable (see
// verify_unlinkability.mjs) so the "no social graph" claim can be checked, not
// taken on faith.

interface StoredBlob {
  readonly ciphertext: Uint8Array;
  readonly expiresAt: number; // ms epoch
}

export interface ServerStateDump {
  /** locator(hex) -> count of blobs waiting. Reveals which mailboxes get traffic. */
  readonly mailboxes: Record<string, number>;
  /** locators(hex) that have a registered verifier (i.e. have ever been claimed). */
  readonly registeredLocators: string[];
  /** What the server CANNOT produce: any sender identity, any deposit→drain link. */
  readonly senderRecords: never[];
  readonly depositToDrainLinks: never[];
}

export class DropServer {
  private readonly store = new Map<string, StoredBlob[]>();
  private readonly verifiers = new Map<string, Uint8Array>(); // locator -> Ed25519 pub
  private readonly challenges = new Map<string, Uint8Array>(); // locator -> open nonce
  private readonly defaultTtlMs: number;

  // A deliberately minimal audit counter. Note what is absent: no sender field,
  // no IP, no deposit-to-drain correlation. Even maximally "logged," the server
  // cannot reconstruct who talks to whom.
  public readonly counters = { deposits: 0, drains: 0, purged: 0 };

  constructor(defaultTtlMs = 24 * 60 * 60 * 1000) {
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * One-time bind of a retrieval verifier (Ed25519 pubkey) to a locator.
   * Trust-on-first-use: the first registration for a locator wins. A real
   * deployment would harden this; the limitation is noted in SPEC §4.3.
   * The pubkey is derived from the owner's Quad-Key and is not linkable to a
   * real-world identity, so the server holding it does not weaken unlinkability.
   */
  register(locatorHex: string, signingPub: Uint8Array): void {
    if (!this.verifiers.has(locatorHex)) {
      this.verifiers.set(locatorHex, signingPub);
    }
  }

  /**
   * INGRESS. Deposit an opaque blob at a locator. No authentication, by design
   * (SPEC §4.2): the server is told nothing about who is depositing.
   */
  deposit(locatorHex: string, ciphertext: Uint8Array, ttlMs?: number): void {
    this.purgeExpired();
    const list = this.store.get(locatorHex) ?? [];
    list.push({ ciphertext, expiresAt: Date.now() + (ttlMs ?? this.defaultTtlMs) });
    this.store.set(locatorHex, list);
    this.counters.deposits++;
  }

  /** EGRESS step 1. Issue a fresh, unpredictable nonce for a locator (SPEC §4.3). */
  challenge(locatorHex: string): Uint8Array {
    const nonce = randomBytes(32);
    this.challenges.set(locatorHex, nonce);
    return nonce;
  }

  /**
   * EGRESS step 2. Release blobs IFF the caller signed the open challenge with
   * the key bound to this locator. The server learns only "the holder of this
   * locator's key drained it" — never who deposited, never a link to senders.
   */
  claim(locatorHex: string, signature: Uint8Array): Uint8Array[] {
    this.purgeExpired();
    const nonce = this.challenges.get(locatorHex);
    const verifier = this.verifiers.get(locatorHex);
    if (!nonce) throw new Error("no open challenge for locator");
    if (!verifier) throw new Error("locator has no registered verifier");

    const ok = ed25519.verify(signature, nonce, verifier);
    if (!ok) throw new Error("signature verification failed");

    this.challenges.delete(locatorHex); // single-use challenge
    const list = this.store.get(locatorHex) ?? [];
    this.store.delete(locatorHex); // drained mailboxes are emptied
    this.counters.drains++;
    return list.map((b) => b.ciphertext);
  }

  /** Unrecoverable purge of expired blobs (SPEC §4.4). */
  purgeExpired(now = Date.now()): void {
    for (const [loc, list] of this.store) {
      const live = list.filter((b) => b.expiresAt > now);
      this.counters.purged += list.length - live.length;
      if (live.length) this.store.set(loc, live);
      else this.store.delete(loc);
    }
  }

  /**
   * Produce the server's COMPLETE observable state. This is what an adversary
   * who seized the server would have. The point of the types: the social graph
   * is not representable — senderRecords and depositToDrainLinks are `never[]`,
   * always empty, because the server never had that data to begin with.
   */
  dumpState(): ServerStateDump {
    const mailboxes: Record<string, number> = {};
    for (const [loc, list] of this.store) mailboxes[loc] = list.length;
    return {
      mailboxes,
      registeredLocators: [...this.verifiers.keys()],
      senderRecords: [],
      depositToDrainLinks: [],
    };
  }
}

// ===========================================================================
//  CLIENT HELPERS — tie the Specter Layer to a Spirit-Layer identity
// ===========================================================================
//
// These accept the minimal key material rather than importing the full Identity
// type, so the transport module stays usable on its own. In the integration
// test (test-vectors/integration.mjs) they are driven by real derived
// identities from identity.ts.

export interface SendTarget {
  readonly locatorHex: string; // recipient's locator (public address)
  readonly encryptionPublic: Uint8Array; // recipient's X25519 pub
}

export interface ReceiveIdentity {
  readonly locatorHex: string;
  readonly signingPrivate: Uint8Array; // Ed25519 seed
  readonly signingPublic: Uint8Array;
  readonly encryptionPrivate: Uint8Array; // X25519 priv
}

/** Send a UTF-8 message to a target via the dead-drop. Sender stays anonymous. */
export function sendMessage(server: DropServer, target: SendTarget, text: string): void {
  const blob = seal(target.encryptionPublic, new TextEncoder().encode(text));
  server.deposit(target.locatorHex, blob);
}

/** Drain and decrypt all messages waiting for `me`. */
export function receiveMessages(server: DropServer, me: ReceiveIdentity): string[] {
  // Bind verifier on first use, then run the challenge-response.
  server.register(me.locatorHex, me.signingPublic);
  const nonce = server.challenge(me.locatorHex);
  const sig = ed25519.sign(nonce, me.signingPrivate);
  const blobs = server.claim(me.locatorHex, sig);
  return blobs.map((b) => new TextDecoder().decode(unseal(me.encryptionPrivate, b)));
}

export { toHexKey };
