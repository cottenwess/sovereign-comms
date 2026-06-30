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
 *   - The SEALED-BOX path (seal/unseal) is NOT forward secret. It gives
 *     SENDER ANONYMITY (ephemeral-static X25519 + XChaCha20-Poly1305), which is
 *     exactly what the pre-session Lobby flow needs (SPEC §5.7 step 2), and it
 *     remains the right tool there. In-channel conversation now has a forward-
 *     secret path: RatchetSession below routes per-message keys from the
 *     symmetric ratchet (src/ratchet.ts) through the committing envelope
 *     (SPEC §6.2). Compromise of long-term keys still exposes past SEALED-BOX
 *     blobs; it does not expose past RatchetSession messages.
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

import { x25519 } from "@noble/curves/ed25519.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";
import { commitSeal, commitOpen, NONCE_LEN } from "./envelope.js";
import {
  initRatchet,
  ratchetSend,
  ratchetReceive,
  type HandshakeInput,
  type RatchetState,
  type RatchetHeader,
} from "./ratchet.js";

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
// The AEAD layer is wrapped in the committing envelope (envelope.ts, SPEC
// §6.1.1) so a single blob cannot be made to open under two keys (Invisible
// Salamanders). The ephemeral public key is bound in as associated data.
//
// Wire layout of a sealed blob:
//   [ ephemeral_pub (32) | committing_envelope ]
//   where committing_envelope = commit(32) | nonce(24) | aead_ciphertext

const EPH_LEN = 32;

function deriveBoxKey(shared: Uint8Array): Uint8Array {
  // Domain-separate the raw ECDH output before using it as a message key.
  return hkdf(sha256, shared, undefined, new TextEncoder().encode("ghostbox/v1/sealedbox"), 32);
}

/** Encrypt `message` to a recipient's X25519 public key. Sender is anonymous. */
export function seal(recipientX25519Pub: Uint8Array, message: Uint8Array): Uint8Array {
  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientX25519Pub);
  const key = deriveBoxKey(shared);
  const nonce = randomBytes(NONCE_LEN);
  // The ephemeral pubkey is authenticated as associated data, binding the blob
  // to this sender ECDH and into the key commitment.
  const envelope = commitSeal(key, message, nonce, ephPub);

  const out = new Uint8Array(EPH_LEN + envelope.length);
  out.set(ephPub, 0);
  out.set(envelope, EPH_LEN);
  // best-effort wipe of ephemeral private + shared secret + message key
  ephPriv.fill(0);
  shared.fill(0);
  key.fill(0);
  return out;
}

/** Decrypt a sealed blob using the recipient's X25519 private key. */
export function unseal(recipientX25519Priv: Uint8Array, blob: Uint8Array): Uint8Array {
  const ephPub = blob.subarray(0, EPH_LEN);
  const envelope = blob.subarray(EPH_LEN);
  const shared = x25519.getSharedSecret(recipientX25519Priv, ephPub);
  const key = deriveBoxKey(shared);
  // commitOpen recomputes and constant-time-checks the commitment BEFORE the
  // AEAD runs, rejecting a partitioning attempt up front.
  const pt = commitOpen(key, envelope, ephPub);
  shared.fill(0);
  key.fill(0);
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



// ===========================================================================
//  RATCHET SESSION — forward-secret in-channel messaging (SPEC §6.2)
// ===========================================================================
//
// One RatchetSession per Ghost Channel per party. The channel address IS the
// session selector: §5.8 requires each relationship's channel independently
// keyed, so a blob's mailbox identifies its session and the cleartext header
// carries only a message number — no sender tag, nothing the server can graph.
//
// Wire layout of a session blob:
//   [ messageNumber (u32be, 4) | committing_envelope ]
// The 4 header bytes are the envelope's associated data, so the number that
// selected the key is authenticated by the key it selected: tamper with the
// header and the derived key changes, the commitment check fails, and the blob
// is rejected before AEAD decryption (envelope.ts).
//
// ANTI-DOS INVARIANT (deposits are unauthenticated — SPEC §4.2)
//   Anyone can deposit junk at a channel address. Ratchet state therefore
//   COMMITS ONLY when a blob fully authenticates: receive() snapshots the
//   state, attempts ratchet-step + commitOpen, and rolls back on ANY failure.
//   A forged header cannot burn message numbers, poison the skipped-key cache,
//   or push the chain toward the MAX_SKIP cap.

const HEADER_LEN = 4;

function encodeHeader(h: RatchetHeader): Uint8Array {
  const out = new Uint8Array(HEADER_LEN);
  out[0] = (h.messageNumber >>> 24) & 0xff;
  out[1] = (h.messageNumber >>> 16) & 0xff;
  out[2] = (h.messageNumber >>> 8) & 0xff;
  out[3] = h.messageNumber & 0xff;
  return out;
}

function decodeHeader(b: Uint8Array): RatchetHeader {
  return { messageNumber: ((b[0]! << 24) | (b[1]! << 16) | (b[2]! << 8) | b[3]!) >>> 0 };
}

function snapshotState(s: RatchetState): RatchetState {
  return {
    sendChainKey: new Uint8Array(s.sendChainKey),
    recvChainKey: new Uint8Array(s.recvChainKey),
    sendCount: s.sendCount,
    recvCount: s.recvCount,
    skipped: new Map([...s.skipped.entries()].map(([n, k]) => [n, new Uint8Array(k)])),
  };
}

function restoreState(into: RatchetState, from: RatchetState): void {
  into.sendChainKey.set(from.sendChainKey);
  into.recvChainKey.set(from.recvChainKey);
  into.sendCount = from.sendCount;
  into.recvCount = from.recvCount;
  into.skipped.clear();
  for (const [n, k] of from.skipped) into.skipped.set(n, k);
}

/** The peer's channel mailbox this session deposits into. */
export interface ChannelSendTarget {
  readonly locatorHex: string;
}

/** This party's channel mailbox and the credentials to drain it. */
export interface ChannelReceiveCredentials {
  readonly locatorHex: string;
  readonly signingPrivate: Uint8Array; // Ed25519 seed
  readonly signingPublic: Uint8Array;
}

export interface SessionReceiveResult {
  /** Decrypted messages, in drain order. */
  readonly accepted: string[];
  /** Blobs rejected without mutating ratchet state (junk, tampering, replays). */
  readonly rejected: number;
}

export class RatchetSession {
  /** Live ratchet state. Exposed for §6.4 state-sync serialization only. */
  readonly state: RatchetState;
  readonly outbound: ChannelSendTarget;
  readonly inbound: ChannelReceiveCredentials;

  constructor(state: RatchetState, outbound: ChannelSendTarget, inbound: ChannelReceiveCredentials) {
    this.state = state;
    this.outbound = outbound;
    this.inbound = inbound;
  }

  /** Advance the send chain one step and wrap `plaintext` for the wire. */
  sealNext(plaintext: Uint8Array): Uint8Array {
    const { messageKey, header } = ratchetSend(this.state);
    const headerBytes = encodeHeader(header);
    const nonce = randomBytes(NONCE_LEN);
    const envelope = commitSeal(messageKey, plaintext, nonce, headerBytes);
    messageKey.fill(0);
    const out = new Uint8Array(HEADER_LEN + envelope.length);
    out.set(headerBytes, 0);
    out.set(envelope, HEADER_LEN);
    return out;
  }

  /**
   * Open one session blob. TRANSACTIONAL: on any failure (short blob, forged
   * header, commitment mismatch, AEAD failure, replay, skip-cap breach) the
   * ratchet state is restored to its value before the call, then the error is
   * rethrown. State advances only for authenticated blobs.
   */
  openBlob(blob: Uint8Array): Uint8Array {
    if (blob.length < HEADER_LEN) throw new Error("session blob too short");
    const before = snapshotState(this.state);
    try {
      const headerBytes = blob.subarray(0, HEADER_LEN);
      const messageKey = ratchetReceive(this.state, decodeHeader(headerBytes));
      const pt = commitOpen(messageKey, blob.subarray(HEADER_LEN), headerBytes);
      messageKey.fill(0);
      return pt;
    } catch (e) {
      restoreState(this.state, before);
      throw e;
    }
  }

  /** Forward-secret send: seal the next message and deposit it at the peer's mailbox. */
  send(server: DropServer, text: string): void {
    server.deposit(this.outbound.locatorHex, this.sealNext(new TextEncoder().encode(text)));
  }

  /**
   * Drain this party's channel mailbox and open every blob. Undecryptable
   * blobs are counted and dropped without touching ratchet state (see the
   * anti-DoS invariant above); the channel stays healthy under junk deposits.
   */
  receive(server: DropServer): SessionReceiveResult {
    server.register(this.inbound.locatorHex, this.inbound.signingPublic);
    const nonce = server.challenge(this.inbound.locatorHex);
    const sig = ed25519.sign(nonce, this.inbound.signingPrivate);
    const blobs = server.claim(this.inbound.locatorHex, sig);

    const accepted: string[] = [];
    let rejected = 0;
    for (const blob of blobs) {
      try {
        accepted.push(new TextDecoder().decode(this.openBlob(blob)));
      } catch {
        rejected++;
      }
    }
    return { accepted, rejected };
  }
}

/**
 * Establish a forward-secret session from a completed handshake.
 *
 * INTEGRATION SEAM (deliberate): the triple-DH needs both parties' ephemeral
 * public keys, and HOW those ephemerals cross the wire is the Corporeal Layer
 * Lobby handshake (SPEC §5.7) — roadmap item #3, not yet implemented. Until it
 * lands, callers obtain the HandshakeInput out of band (tests construct it
 * directly). This function is the single point that boundary will plug into.
 */
export function establishSession(
  handshake: HandshakeInput,
  outbound: ChannelSendTarget,
  inbound: ChannelReceiveCredentials,
): RatchetSession {
  return new RatchetSession(initRatchet(handshake), outbound, inbound);
}

export { toHexKey };
