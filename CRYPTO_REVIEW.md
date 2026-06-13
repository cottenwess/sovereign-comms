# Cryptographic Review Request — GhostBox Protocol v0.4.0

I am asking for adversarial review of the cryptographic design of an open-source, asynchronous dead-drop messaging protocol. This document tells you exactly what it is, what I claim, what I don't claim, where I think it's most likely wrong, and how to look at it. If you find something broken, that is the best possible outcome.

---

## Honest disclosures first

- I am not a professional cryptographer.
- This code is unaudited. No expert has reviewed it. That is why I am asking.
- An AI assistant (Claude, Anthropic) helped design and implement the v0.4.0 forward-secrecy wiring. I directed the decisions; the AI wrote and checked a lot of the code. I am disclosing this because it argues for more scrutiny, not less.
- I did not invent any primitive. Every construction here is composed from established, published pieces. The question is whether I composed them correctly.

---

## What it is, in one paragraph

GhostBox is a zero-identity, asynchronous dead-drop messenger. Two parties exchange messages without the server ever learning who is talking to whom. Identity is user-derived from a set of high-entropy factors (no accounts, no registration, nothing to revoke or seize). The server stores opaque encrypted blobs at unlinkable addresses and is structurally incapable of building a social graph. AT Protocol (Bluesky) integration lets a public handle resolve to a GhostBox address, so public identity comes from AT Proto and private transport comes from GhostBox.

Full specification: [SPECIFICATION.md](./SPECIFICATION.md)
Reference implementation: [github.com/cottenwess/sovereign-comms](https://github.com/cottenwess/sovereign-comms)

---

## The constructions, precisely

### 1. Triple-DH handshake to shared root

Four X25519 Diffie-Hellman operations combining both parties' identity keys and ephemeral keys, combined via HKDF-SHA256 into a shared root secret. Exact transcript in [SPECIFICATION.md §5](./SPECIFICATION.md).

Because the messenger is asynchronous (no live round trip for the handshake), the two parties cannot assign roles by who spoke first. Instead they canonicalize by public-key ordering: the party whose identity public key is lexicographically lower takes the "lo" role. The shared root is derived identically regardless of who initiates.

### 2. Symmetric ratchet for per-message forward secrecy

Per-direction KDF chains derived from the root. Each send or receive advances the chain and derives a fresh message key. The old chain key is replaced and the message key is wiped after use.

This is deliberately a **symmetric** ratchet, not a Double Ratchet. There is no per-message DH step, which means:
- Forward secrecy: **yes.** A stolen message key cannot decrypt past messages.
- Post-compromise security: **no.** If the chain key is stolen, future messages in that direction are exposed until the session is re-established. This is a deliberate tradeoff, not an oversight: identity compromise is permanent by design in this protocol, so post-compromise security would be misleading to claim.

Out-of-order delivery is handled by caching skipped message keys, capped at 64 entries.

### 3. Committing AEAD envelope

Message keys route through a committing AEAD construction before the payload is encrypted. This defends against partitioning attacks (Invisible Salamanders style): a ciphertext cannot be made to authenticate under two different keys. The per-message-number header (4 bytes, big-endian u32) is the associated data, so the number that selected the key is authenticated by the key it selected.

### 4. Transactional receive (anti-DoS)

Deposits to the dead-drop are unauthenticated by design: anyone can drop a blob at any address. To prevent junk deposits from burning message numbers or poisoning the skipped-key cache, the receive path snapshots ratchet state before attempting decryption and rolls back to the snapshot on any failure. Ratchet state advances only when a blob fully authenticates.

### 5. Session selection without sender tags

Each relationship gets its own independently-keyed Ghost Channel (a pair of mailbox addresses, one per direction). The recipient selects the session by which address the blob arrived at, not by any sender tag in the blob. This means the server's complete state contains no sender-to-recipient mapping.

---

## Properties I claim

- **Forward secrecy (in-channel).** Past messages cannot be decrypted with a stolen current key.
- **Application-layer sender/recipient unlinkability.** The server cannot determine who sent a message or who received it.
- **Key commitment.** A ciphertext cannot authenticate under two different keys.
- **Sender anonymity (pre-session Lobby path).** The sealed-box path used for initial contact is ephemeral-static X25519: the server sees no sender identity.

## Properties I do not claim

- Post-compromise security.
- Network-layer anonymity. IP and timing correlation are out of scope; use Tor or a mixnet if that matters.
- Any audit or independent verification.
- The AT Proto bridge is anonymous. Publishing a locator to a public record trades unlinkability for discoverability. This is documented as a deliberate tradeoff.

---

## Where I think it is most likely wrong

Start here.

**1. Handshake role canonicalization.** The lo/hi public-key ordering avoids a live round trip but introduces a static structure. Does this open a reflection attack, an identity-misbinding path, or a MITM opportunity where an attacker substitutes ephemerals? Is the peer's identity key bound into the root tightly enough?

**2. Forward secrecy vs the skipped-key cache.** Skipped message keys sit in memory until consumed or the cap forces eviction. Does this undercut the forward-secrecy claim beyond the obvious in-memory window? Are the chain-key and message-key derivations domain-separated correctly from each other and from the root?

**3. The committing AEAD construction.** Does it actually commit to the full key, or is there a gap in the binding? Is the message-number header as AD sufficient to prevent a tampered header from steering decryption to a different key path?

**4. The transactional receive.** The snapshot-and-rollback approach assumes no side effects escape before the rollback. Is there any state-exhaustion path, timing channel, or partial-state leak that the rollback misses?

**5. The 3DH composition.** The four DH outputs are concatenated and passed to HKDF as input key material. Is the concatenation safe, or does it need a more careful binding to prevent a party from canceling another party's contribution?

---

## How to look at it

```
git clone https://github.com/cottenwess/sovereign-comms
cd sovereign-comms
npm ci
npm run test:all        # ten jobs, all green
```

The relevant files:

| File | What it is |
|---|---|
| `SPECIFICATION.md` | The normative spec. Start here for exact transcripts. |
| `src/ratchet.ts` | The symmetric ratchet: triple-DH, KDF chains, skip logic. |
| `src/transport.ts` | `RatchetSession`: the ratchet wired into the dead-drop. |
| `src/envelope.ts` | The committing AEAD envelope. |
| `src/statesync.ts` | Ratchet-state serialization for the sync channel. |
| `test-vectors/fs-transport.mts` | End-to-end test including attack scenarios. |
| `test-vectors/ratchet.mts` | Ratchet unit tests and frozen vectors. |

---

## If you find something

Open an issue, or use GitHub's private vulnerability reporting (Security tab) if you prefer not to disclose publicly before it's fixed. You will be credited in any subsequent advisory or design revision.

I will respond quickly. A finding that changes the design is the best possible outcome of posting this.

---

*GhostBox Protocol v0.4.0. Architecture by Cory A. Ottenwess. Companion text: Notes from an Acceleration Native. License: AGPL-3.0.*
