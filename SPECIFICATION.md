# The Sovereign Communication & Permissions Specification

**A unified technical specification for the GhostBox Protocol and the Companion Permissions Layer**

| | |
|---|---|
| **Version** | 0.1.0 (Draft) |
| **Status** | Working draft — open for implementation and review |
| **Date** | May 2026 |
| **License** | (assign before publishing — see §0.4) |
| **Companion text** | *Notes from an Acceleration Native*, Appendix B & Chapter 11 |

---

## 0. About This Document

### 0.1 What this is

This is an implementation reference for two interlocking pieces of sovereignty infrastructure:

1. **The GhostBox Protocol** — a zero-identity, asynchronous, dead-drop communication protocol. It lets two parties exchange messages and assets without the transport infrastructure ever learning who is talking to whom.
2. **The Companion Permissions Layer** — the access-control model that sits between a user's personal data vault and the outside world, mediated by an AI companion that acts as a non-bribable gatekeeper.

These are specified together because they share one design decision applied at two layers: **remove the intermediary's ability to extract value from a user's data by removing the intermediary's access to that data.** GhostBox applies it to message transport. The Permissions Layer applies it to vault access. Either is buildable alone; together they close the loop.

### 0.2 What this is not

This document does not specify the personal data vault's storage format, the companion's reasoning model, or the Model Context Protocol (MCP) itself. Those are separate prerequisites with their own specifications. This document specifies the *boundary* — how the world reaches the vault, and how the vault reaches the world — not the contents on either side.

### 0.3 How to read the requirement language

This spec uses RFC 2119 / RFC 8174 keywords. **MUST**, **MUST NOT**, **REQUIRED**, **SHALL** are absolute. **SHOULD**, **SHOULD NOT**, **RECOMMENDED** mean there may be valid reasons to deviate, but the full implications must be understood first. **MAY** and **OPTIONAL** are genuinely discretionary.

A conformant implementation MUST satisfy every MUST in §2–§6. Everything in §7 (Companion Permissions) is REQUIRED for a system that claims to be a "sovereign companion deployment" but OPTIONAL for a system that implements GhostBox transport alone.

### 0.4 Divergences from the published book text

The book's Appendix B contains illustrative reference code. This spec corrects three things for production use and flags them so the difference is intentional, not a contradiction:

- **Salt derivation.** Appendix B's example uses static salts (`b'static_salt_for_locator'`). That is a documentation simplification. This spec REQUIRES salts bound to the Quad-Key composite (§3.3). Static salts make identities collide across users and enable precomputed-table attacks.
- **Argon2id parameters.** The book quotes one parameter set. This spec defines a versioned parameter ladder (§3.4) so the cost can rise over time without breaking existing identities.
- **HKDF construction.** An earlier version of §3.3 and §6.5 illustrated the per-composite salt using a single `HMAC(label, composite)` call, which is HKDF-Extract only — not full RFC 5869 HKDF. The salt MUST be derived with Extract **then** Expand (§3.3). The reference implementation (§6.5) has been corrected accordingly, and the cross-language test vectors (§6.5) were regenerated from the corrected code. Where an older local copy of this spec shows the single-HMAC form, this version governs.

Where this document and the book disagree, **this document governs for implementers.**

---

## 1. Design Principles

These are normative. Every later requirement traces back to one of them.

**P1 — Possession is identity.** Identity MUST be derivable by the user from secrets and factors they hold, with no registration step and no server-held account record. There is nothing for a platform to revoke, suspend, or sell, because no platform holds it.

**P2 — The server cannot build the graph.** The transport infrastructure MUST be structurally incapable of linking sender to recipient. This is a mathematical property of the design, not a policy promise. The social graph must not exist in the server's data in any recoverable form.

**P3 — Extraction incentive absent by construction.** No component that mediates access to user data MAY have a financial relationship with parties seeking that data. The gatekeeper cannot be bribed because the revenue model that would reward letting someone in does not exist.

**P4 — Trust is verifiable, not declared.** Every component that handles user data MUST be auditable: open code, public governance, behavior checkable against this specification. Trust is earned through inspection, the way a contract is trustworthy — terms written down, deviation detectable — not extended on faith.

**P5 — Presence mirrors social reality.** The relationship model MUST represent the full gradient of human connection, not a connected/not-connected binary. Access is scoped, revocable, and user-defined at every stage.

**P6 — The user decides; the companion holds.** The companion MUST NOT advance trust, widen access, or alter a permission on its own authority. It maintains the shape of what the user has decided, flags when that shape may need revisiting, and waits for affirmation before anything changes.

---

## 2. System Architecture: The Spectre Stack

GhostBox is organized as three independent layers. Independence is a hard requirement: **compromise of one layer MUST NOT compromise another.** Each is progressively more "tangible" — from the invisible and private, through the permissioned and accessible, to the voluntary and present.

```
┌─────────────────────────────────────────────────────────────┐
│  CORPOREAL LAYER (Discovery)                                  │
│  Voluntary presence. How parties find each other.            │
│  Public Mask · Lobby · Ghost Channel · 4 discovery modes     │
│  5-state relationship model                                   │
├─────────────────────────────────────────────────────────────┤
│  SPECTER LAYER (Transport)                                    │
│  Passive dead-drop. The server that cannot link.             │
│  PUT to Locator Hash · challenge-response GET · TTL purge    │
├─────────────────────────────────────────────────────────────┤
│  SPIRIT LAYER (Identity)                                      │
│  Invisible. Exists only in user memory + transient RAM.      │
│  Quad-Key → Argon2id → Locator Hash (public) + Access Token  │
└─────────────────────────────────────────────────────────────┘
            ▲                                    ▲
            │                                    │
   ┌────────┴─────────┐              ┌───────────┴────────────┐
   │  PERSONAL VAULT  │◄────────────►│   COMPANION PERMISSIONS │
   │  (out of scope)  │   gated by   │   LAYER  (§7)           │
   └──────────────────┘              └─────────────────────────┘
```

The Companion Permissions Layer (§7) is not part of the Spectre Stack. It is the consumer of it: the companion uses the Corporeal Layer's relationship model as the vocabulary for vault access control, and uses the Specter Layer as its communication transport.

---

## 3. Spirit Layer — Identity

### 3.1 Overview

The Spirit Layer is invisible. It exists only in the user's memory and, transiently, in device RAM during an active session. No server holds it. No registration touches it. It cannot be seized (no physical location) and cannot be revoked (no third-party administrator).

Identity is mathematical, not administrative. A user generates a **Quad-Key**, and a memory-hard derivation function transforms it into two outputs: a public **Locator Hash** and a private **Access Token**.

### 3.2 The Quad-Key

A Quad-Key is a composite of **four or more** high-entropy factors chosen by the user. The derivation function is agnostic to factor *type*; it requires only sufficient total entropy.

Factors MAY be drawn from any combination of:

| Class | Examples | Notes |
|---|---|---|
| Something you know | passphrases, word sets, codes | Most portable; the original model |
| Something you are | voiceprint / fingerprint / iris / typing-cadence **hashes** | Use as one factor among several — biometrics can't be rotated if leaked |
| Something you have | hardware token, SSI credential, hash of a verified document's properties | The document never enters the system; only a hash of attested properties does |
| Someone who confirms you | designated social-recovery contacts | A protocol the user controls, not a platform reset |

**Requirements:**

- An implementation MUST accept a variable composite — different users will use different factor combinations.
- The composite MUST reach a minimum entropy floor of **128 bits** before derivation proceeds. Implementations MUST measure and enforce this before calling the KDF; entropy MUST NOT be accepted from the caller as a declared value. Conformant enforcement requires all three of the following:
  - **`know` factors**: entropy MUST be measured with an automated estimator (e.g., zxcvbn) applied to the NFC-normalized text. The caller's claimed bit count is ignored.
  - **Per-class caps**: each factor's contribution is bounded regardless of raw estimate — `know` ≤ 80 bits, `are` ≤ 24 bits, `have` ≤ 64 bits, `who` ≤ 64 bits. The `are` cap is hard-low because biometric factors are non-revocable; a leaked biometric hash cannot be changed, so it MUST NOT be load-bearing.
  - **Diversity rule**: no single factor MAY contribute more than half the total measured entropy. This prevents one strong secret from carrying the key alone and forces genuine multi-factor composition.
- The specific factor composition is itself secret. An implementation MUST NOT emit, log, or transmit which factor classes a given identity used. The unpredictability of the composition is a security property (§8).
- Factor inputs MUST be canonicalized before combination (defined byte encoding, defined ordering, defined separator) so the same logical Quad-Key always produces the same composite. Canonicalization rules are in §3.6.

*Example (passphrase-only variant):* `Nebula | 77 | Correct | Horse`

> ⚠️ A passphrase-only Quad-Key is the weakest valid configuration and SHOULD be discouraged in onboarding UX in favor of at least one non-knowledge factor.

### 3.3 Salt (normative — diverges from book and from earlier drafts of this spec)

The derivation MUST use a salt that is:

1. **Bound to the Quad-Key composite**, so two users who happen to choose identical factors do not collide; AND
2. **Deterministic from the composite**, so the same user re-derives the same identity on any device with no stored state.

The REQUIRED construction is **full RFC 5869 HKDF-SHA-256 (Extract then Expand)**, with the composite as the input keying material, an empty salt (filled with 32 zero bytes per RFC 5869 §2.2), and the domain-separation label as the `info` input to Expand:

```
PRK          = HKDF-Extract( salt=0x00×32,               IKM=composite )
salt_locator = HKDF-Expand(  PRK, info="ghostbox/v1/locator", L=32 )
salt_access  = HKDF-Expand(  PRK, info="ghostbox/v1/access",  L=32 )
```

The same PRK is reused for both Expand calls because the IKM (composite) is identical; the distinct `info` labels provide the domain separation. Both outputs are 32-byte per-composite salts fed into Argon2id.

Implementations MUST NOT use a single static salt shared across users. Implementations MUST NOT substitute a bare `HMAC(label, composite)` for HKDF: that construction is Extract-only, omits Expand, and produces different output than the above — cross-implementation parity is lost. (This was the error in an earlier illustrative snippet; the cross-language test vectors in §6.5 were regenerated after the correction.)

### 3.4 Derivation function and parameter ladder

The KDF MUST be **Argon2id**. Parameters are versioned so cost can rise over time without invalidating existing identities — the version is encoded in the public alias record (§5) so a recipient knows which ladder rung to use.

| Param set | memory | iterations | parallelism | target time (reference device) |
|---|---|---|---|---|
| `argon2id-v1` | 64 MiB (65536 KiB) | 4 | 4 | < 2 s |
| `argon2id-v2` | 256 MiB | 4 | 4 | < 2 s (2026+ hardware) |
| `argon2id-v3` | reserved | — | — | — |

- New identities SHOULD use the highest non-reserved version the device can complete in under 2 seconds.
- An implementation MUST support deriving against any non-reserved historical version, because existing identities depend on them.
- Output lengths: Locator Hash = 16 bytes; Access Token seed = 32 bytes.

### 3.5 Outputs

**Locator Hash (public).** The address of the user's Drop-Box. Others use it to send. Knowing a Locator Hash grants the ability to *deposit* an encrypted blob — nothing more. It does not grant read access.

**Access Token (private).** The credential used to sign retrieval challenges and to derive the long-term key material that decrypts content. The server MUST NEVER receive it. It is used only client-side, to prove authorization to drain a Drop-Box.

```
Quad-Key (composite, in RAM only)
        │
        ├── canonicalize ──► composite bytes
        │
        ├── HKDF ──► salt_locator ──► Argon2id ──► Locator Hash (PUBLIC, 16B)
        │
        └── HKDF ──► salt_access  ──► Argon2id ──► Access Token  (PRIVATE, 32B)
```

The Access Token seed MUST additionally be used to derive a signing keypair (Ed25519 RECOMMENDED) for challenge-response (§4.3) and an X25519 keypair for message encryption (§6).

### 3.6 Canonicalization (REQUIRED)

To guarantee deterministic re-derivation:

- Each factor is reduced to bytes: text factors → NFC-normalized UTF-8; biometric/document factors → their hash output (fixed length).
- Factors are concatenated in **user-fixed order** (the order chosen at creation, stored nowhere; the user must reproduce it). Order is part of the secret.
- Separator between factors MUST be a single `0x1F` (unit separator) byte, which cannot appear inside NFC text or fixed-length hashes.
- The concatenated result is the *composite* fed to HKDF.

### 3.7 Duress identity

An implementation SHOULD support a secondary **Duress Quad-Key** that derives a distinct, plausibly-innocuous identity:

- Entering the duress composite MUST open an account indistinguishable from a real-but-empty account.
- The real identity MUST remain cryptographically invisible — nothing in app state, storage, or network behavior may reveal a second identity exists.
- The two identities MUST share no derivable link.

---

## 4. Specter Layer — Transport

### 4.1 The dead-drop model

The server is a **passive, dumb storage facility.** It is not a post office; it does not route, and it does not know who sent what to whom. It is a location where encrypted blobs are left and retrieved without either party being present simultaneously, known to each other, or known to the server.

This is what enforces **P2**.

### 4.2 Ingress (sending)

```
SENDER                                    SERVER
  │  encrypt(blob, recipient_X25519_pub)
  │  PUT  /drop/{recipient_locator_hash}
  │       body = ciphertext
  ├─────────────────────────────────────►│  store ciphertext at locator_hash
  │                                        │  (TTL clock starts)
  │  ◄──────── 202 Accepted ──────────────┤
```

Requirements:

- The server MUST store the blob at the addressed Locator Hash without recording sender identity or sender IP in association with the deposit.
- The server MUST NOT require sender authentication. Anyone may deposit to any Locator Hash. (Spam/flood mitigation is handled at the Corporeal Layer via the Lobby, §5.2, not by identifying senders.)
- The server MUST treat the blob as opaque bytes. It MUST NOT attempt to parse, index, or inspect contents.
- Sender transport SHOULD be anonymized at the network layer (e.g., over Tor or a mixnet) since IP-level correlation is outside the protocol's cryptographic guarantees (§8.4).

### 4.3 Egress (receiving)

Retrieval is challenge-response so the server releases a blob only to the holder of the Access Token — without the server learning the Access Token or linking the drain to any prior deposit.

```
RECIPIENT                                 SERVER
  │  GET /drop/{my_locator_hash}
  ├─────────────────────────────────────►│
  │  ◄──────── challenge (nonce) ─────────┤  fresh random nonce
  │  sign(nonce, access_signing_key)       │
  │  POST /drop/{my_locator_hash}/claim    │
  │       body = signature                 │
  ├─────────────────────────────────────►│  verify sig against pubkey
  │                                        │  bound to this locator hash
  │  ◄──────── ciphertext blob(s) ─────────┤  release + (per TTL) mark/purge
```

Requirements:

- The server MUST issue a fresh, unpredictable nonce per challenge.
- The server MUST verify the signature against the public key associated with that Locator Hash. **How the server learns that pubkey without learning identity:** the pubkey is registered at first deposit-claim as an opaque verifier bound to the Locator Hash; it is not linkable to any real-world identity and is itself derived from the Quad-Key.
- The server MUST NOT log a linkage between a claim event and any prior deposit event. Deposit and drain MUST be independently unlinkable in server records.
- The server sees a deposit, and separately a challenge-response drain. It MUST be unable to determine that the depositor and the drainer are in a relationship.

### 4.4 Retention / TTL

- Every stored blob MUST carry a TTL. Default free-tier TTL is **24 hours**; unretrieved blobs MUST be purged at expiry.
- Purge MUST be unrecoverable (overwrite or cryptographic erasure, not a "deleted" flag).
- Paid/enterprise tiers MAY extend TTL (§9).

### 4.5 What the Specter Layer also carries

The dead-drop is not messaging-only. Any exchange that needs to move *something* between two parties without disclosing identity to each other or to the infrastructure operates here: message blobs, asset transfers, the encrypted Tier-2 address handoff during a handshake (§5.6), and read-receipt tokens (§6.4).

---

## 5. Corporeal Layer — Discovery

### 5.1 Overview

The Corporeal Layer is where a user has voluntary presence: somewhere they can be found, by people and institutions they choose, on terms they set, without exposing a permanent harvestable identifier. It answers the question the dead-drop creates — *if identity is private and device-agnostic, how do two parties find each other?*

It has three structural components and four discovery modes, all governed by one five-state relationship model.

### 5.2 Structural components

**Public Mask** — a voluntary alias listed in a distributed hash table (DHT), pointing to the user's Lobby. OPTIONAL per user. A user with no Public Mask is undiscoverable except by proximity (§5.4).

**Lobby** — a filtering Drop-Box for inbound connection requests. It is a Tier-1 address: deliberately disposable and rotatable. Flooding the Lobby costs the attacker nothing but reveals nothing and reaches nothing past the filter. The Lobby is the spam firewall that replaces sender-identification.

**Ghost Channel** — a unique, private, per-relationship communication address (Tier-2). Generated once a connection is accepted; thereafter the Lobby is no longer involved for that relationship. Each relationship gets its own Ghost Channel, so revoking one (§5.8) leaks nothing about the others.

### 5.3 Discovery Mode 1 — Public Alias

Anyone who knows the alias deposits a connection request (their X25519 public key) into the Lobby. The owner polls, reviews, and approves or ignores. On approval, a fresh Tier-2 Ghost Channel is generated for that relationship alone. For users who want to be publicly findable: a professional surface, a public persona, a business presence. The alias persists only as long as chosen; the underlying identity stays invisible.

### 5.4 Discovery Mode 2 — Proximity Handshake

Two GhostBox users in physical proximity can connect without either holding a public alias.

- Companions detect shared context (same location, same moment) via existing radio presence — Bluetooth / ultra-wideband — and derive an **ephemeral proximity key** from that shared context.
- Neither party discloses alias or identity. Each companion surfaces a prompt: *someone nearby is open to connection.*
- If both accept, a temporary introduction channel opens. If either chooses to proceed, a full Tier-2 Ghost Channel is established.
- The proximity key MUST be destroyed immediately after use. It served one moment and is gone.

This is the protocol's strongest privacy posture: a user with no alias, no Lobby, and no listed presence is completely invisible *except* in the instant they choose to be available. The moment passes; they are invisible again. This mode is the substrate for the companion's expo/business-card intake (§7.6).

### 5.5 Discovery Mode 3 — Mediated Introduction

The mutual-friend model. Alice knows both you and Bob and wants to introduce you. Alice's companion creates a **bounded, temporary group introduction context** — not a permanent shared channel:

- Alice vouches for both parties; each can see enough of the other to decide.
- Alice does not disclose either identity to the other; she attests trust and lets each decide.
- If it goes well, a direct Ghost Channel is established between you and Bob, **independent of Alice** — she cannot access it and her participation is not required to sustain it.
- If it does not, the context closes, nothing persists, Bob remains a Stranger.

### 5.6 Discovery Mode 4 — Relayed Social Connection

For indirect introductions through a chain of existing trust (your mother → your aunt). The introduction travels the companion chain with implicit vouching at each hop. You receive a notification naming the introducer and the nature of the request, and you MAY grant a **temporary, scoped** access window (a ride from the airport; a week of limited contact). When the window closes, it closes; the contact returns to the periphery — known, not connected — unless you choose otherwise.

This encodes what every existing platform ignores: the difference between a person you've met and one you haven't, between a contact you trust and one you'll tolerate temporarily, between a relationship that deserves a permanent channel and one that deserved a single afternoon.

### 5.7 The Handshake (wire sequence)

```
1. Bob resolves @Alice via the DHT → Alice's Lobby (Tier-1) address.
2. Bob PUTs a connection request (his X25519 pubkey, optional intro note),
   encrypted to Alice's published pubkey, into Alice's Lobby.
3. Alice polls her Lobby, reviews the request.
4. Alice accepts → her client generates a NEW unique Tier-2 Ghost Channel address.
5. Alice encrypts the Tier-2 address to Bob's pubkey, deposits it in her Lobby.
6. Bob drains it, both switch to the Tier-2 channel. Lobby is done for this pair.
```

All deposits/drains above ride the Specter Layer (§4) and inherit its unlinkability.

### 5.8 The Five-State Relationship Model

User-defined and user-controlled at every stage. **Not** platform categories.

| State | Channel | Access | Notes |
|---|---|---|---|
| **Stranger** | none | none, no visibility | Default for everyone not admitted via a discovery mode |
| **Acquaintance** | exists, bounded | scoped: time-, purpose-, or interaction-limited | Holdable indefinitely with no obligation to advance |
| **Preliminary** | full Ghost Channel | open, but flagged provisional | Either party may step back to Acquaintance cleanly, with **no demotion notice** to the other |
| **Established** | persistent | mutual, at agreed scope | The single state most platforms collapse everything into |
| **Revoked** | destroyed | none, no trace | Not "blocked" (which notifies). Revoked = gone. The revoked party is not told; messages simply stop being received. |

Requirements:

- Transitions MUST be initiated by the user (or by the companion *only after user affirmation*, per **P6**).
- A demotion (Preliminary → Acquaintance, or any → Revoked) MUST NOT notify the affected party. "The system does not perform social awkwardness on your behalf."
- Revocation MUST destroy the relationship's Ghost Channel and leave no residual record linkable to the revoked party.
- Each relationship's Ghost Channel MUST be independently keyed so that state changes on one never expose another.

---

## 6. Cryptographic Requirements

### 6.1 Primitives

| Purpose | Primitive | Status |
|---|---|---|
| Key derivation | Argon2id (versioned, §3.4) | MUST |
| Salt expansion | HKDF-SHA-256 | MUST |
| Message encryption | Double Ratchet over X25519 + AEAD (XChaCha20-Poly1305 RECOMMENDED) | MUST |
| Signatures (challenge-response) | Ed25519 | RECOMMENDED |
| Hashing | SHA-256 / BLAKE2 | MUST |

### 6.2 Forward secrecy

Message encryption MUST use the **Double Ratchet Algorithm** (the construction underlying Signal). Compromise of the Quad-Key in the future MUST NOT decrypt past messages encrypted under prior session keys.

### 6.3 Device agnosticism

Because possession is identity (**P1**), a user MUST be able to access their queue from any device: install client → enter Quad-Key → derive in RAM → access. On exit, **all local data MUST be wiped.** No device-specific credential and no server-side recovery process may exist.

### 6.4 Zero-knowledge read receipts

Read confirmation MUST NOT create a server-side metadata trail:

```
1. Bob embeds an opaque Receipt Token inside the encrypted message envelope.
2. Alice decrypts, extracts the Token.
3. Alice's client deposits the Token in Bob's Drop-Box (a normal Specter-layer PUT).
4. Bob's client drains it, marks the message read.
```

The server processes an unrelated deposit and drain. It MUST be unable to link them to each other or to the original message — so read state propagates without the server knowing a message was sent, let alone read.

### 6.5 Reference: identity derivation (corrected)

> This replaces the book's illustrative snippet and corrects an earlier version of this section. Changes from the previous version of this spec: (1) `hkdf_salt` now performs full RFC 5869 HKDF (Extract then Expand) matching §3.3, not a bare HMAC-Extract; (2) entropy is measured with zxcvbn, not declared by the caller; (3) per-class caps and the diversity rule are enforced (§3.2); (4) the composite is zeroed in a `finally` block; (5) keypair derivation from the Access Token seed is shown. The cross-language test vectors were regenerated from this corrected construction.

```python
import math, unicodedata
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.hashes import SHA256
from zxcvbn import zxcvbn as _zxcvbn

UNIT_SEP    = b"\x1f"
ENTROPY_MIN = 128   # bits
CLASS_CAP   = {"know": 80, "are": 24, "have": 64, "who": 64}

def _hkdf(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    # Full RFC 5869 HKDF-SHA256, salt=None -> 0x00*32 per spec.
    # Extract: PRK = HMAC-SHA256(key=0x00*32, msg=ikm)
    # Expand:  OKM = HMAC-SHA256(key=PRK, msg=info || 0x01)[:length]
    return HKDF(SHA256(), length, salt=None, info=info).derive(ikm)

def assert_entropy_floor(factors: list) -> None:
    bits = []
    for f in factors:
        if f["class"] == "know":
            raw = math.log2(max(_zxcvbn(f["text"])["guesses"], 2))
        else:
            raw = f["declared_bits"]  # hashed/token factors declare; caller is responsible
        bits.append(min(raw, CLASS_CAP[f["class"]]))
    total = sum(bits)
    if total < ENTROPY_MIN:
        raise ValueError(f"entropy {total:.1f} bits < required {ENTROPY_MIN}")
    if max(bits) > total / 2:
        raise ValueError("no single factor may supply more than half the entropy floor")

def canonicalize(factors: list) -> bytearray:
    # factors already reduced to bytes by caller:
    #   "know" -> NFC-normalized UTF-8; others -> fixed-length hash digest
    # order is user-fixed and part of the secret
    parts = [unicodedata.normalize("NFC", f["text"]).encode()
             if f["class"] == "know" else f["digest"]
             for f in factors]
    buf = bytearray()
    for i, p in enumerate(parts):
        buf += p
        if i < len(parts) - 1:
            buf += bytearray([0x1F])
    return buf  # mutable bytearray so it can be zeroed; caller MUST zero after use

def derive_identity(factors: list, argon_params: dict):
    assert_entropy_floor(factors)       # raises if below floor or diversity rule fails
    composite = canonicalize(factors)   # bytearray; zeroed in finally
    try:
        salt_loc = _hkdf(bytes(composite), b"ghostbox/v1/locator")
        salt_acc = _hkdf(bytes(composite), b"ghostbox/v1/access")

        locator     = Argon2id(salt=salt_loc, length=16, **argon_params).derive(bytes(composite))
        access_seed = Argon2id(salt=salt_acc, length=32, **argon_params).derive(bytes(composite))

        sign_seed = _hkdf(access_seed, b"ghostbox/v1/sign")  # seeds Ed25519 signing keypair
        enc_seed  = _hkdf(access_seed, b"ghostbox/v1/enc")   # seeds X25519 encryption keypair

        return locator.hex(), access_seed   # access_seed stays in RAM only
    finally:
        composite[:] = b"\x00" * len(composite)   # best-effort wipe; see SECURITY.md

# argon2id-v1
PARAMS_V1 = dict(iterations=4, lanes=4, memory_cost=65536)
```

The memory-hard parameters keep brute force expensive even for well-resourced adversaries while holding derivation under ~2 seconds on a normal device. The `finally` wipe is best-effort only: text factors that existed as strings before reaching this layer cannot be wiped from managed-runtime heap memory. See SECURITY.md for a full treatment of the erasure ceiling.

---

## 7. The Companion Permissions Layer

> REQUIRED for a "sovereign companion deployment"; OPTIONAL for a GhostBox-transport-only implementation.

### 7.1 Role

The companion has two jobs. One faces the user (synthesize, anticipate, act on authorization). The other faces the world: **it is the world's interface to the vault, and in that capacity its job is to refuse.** This section specifies the refusing.

### 7.2 The non-bribable property (P3)

- The companion MUST have **no financial relationship** with any party seeking access to the user's data. There must be no revenue model that rewards granting access.
- The companion's economic relationship MUST be with the user only (user-paid, provided as infrastructure, or governed under a mandate that makes the user's interest its sole instruction).
- This is a structural requirement, not a behavioral aspiration. A deployment whose operator can monetize access fails this clause regardless of stated policy.

### 7.3 The verifiability property (P4)

A bouncer you cannot trust is worse than no bouncer, because the thing behind the door is the most complete portrait of a person ever assembled in one place. Therefore:

- The companion's code MUST be auditable (open source or independently verifiable build).
- Its governance MUST be public; changes to its operative terms MUST be visible to everyone who depends on it.
- It SHOULD ship with verifiable claims about its own behavior (reproducible builds; attestation). A Know-Your-Agent–style credential (per the New America OTI proposal) MAY be used to let users verify the companion is what it claims to be.

### 7.4 Access decisions and consent granularity

- Every grant MUST be specific (scoped to a purpose), purposeful (tied to a stated use), and revocable at any moment for any reason.
- Authorization of one use MUST NOT imply authorization of any other use. Each use requires its own consent.
- A grant MUST NOT default to broad; the narrowest scope satisfying the stated purpose MUST be the default.
- Grants SHOULD carry expiry by default. Temporary stays temporary; conditional stays conditional.

### 7.5 The access matrix

The companion maintains an **access matrix** mapping each external party (or registered service) to a relationship state (§5.8) and a permission scope. The five-state model is the controlling vocabulary:

| Relationship state | Typical vault scope |
|---|---|
| Stranger | none |
| Acquaintance | acknowledged, held, not opened — e.g., a card captured but no data shared |
| Preliminary | a specific channel + a scoped prompt/context for follow-up |
| Established | mutual access at the scope both parties agreed |
| Revoked | removed, no trace |

### 7.6 Proximity intake (the post-app business card)

When two companion-equipped users have a substantive exchange in proximity, the **proximity handshake (§5.4)** makes intake immediate:

- The two devices exchange a **minimal credential** that places each in the other's access matrix: not preference data, not personal history — the handshake that says *this contact is real, this exchange happened, both parties know it.*
- The credential MUST live in both vaults simultaneously, carry only what each party chose to share, and report to **no platform server**.

The companion captures ambient proximity signals (Bluetooth/UWB presence: duration and proximity, **never audio**) into the vault as a "skeleton of the day." This is existing radio data redirected from platforms into the user's control — not new surveillance. The user's contribution at debrief is **interpretation, not reconstruction**: handed a skeleton and asked what it means, at a moment the companion calibrates, at whatever detail the moment allows. This is the direct answer to the "exhausted user" objection — the labor was done in advance.

### 7.7 The user decides; the companion holds (P6)

- The companion MUST NOT decide how close two people should be, when a professional tie becomes personal, or whether an energetic in-the-moment grant still holds once the user is home and thinking clearly.
- The companion holds the *shape* of permissions already given, flags when observation suggests that shape may need revisiting, and waits for affirmation before changing anything.
- The only question the companion brings back, when it brings one at all, is: **is this still right?**

### 7.8 Self-diagnostic and user-initiated audit

Agreeing to let the companion model you is the start of a relationship, not a one-time setup event; any relationship worth having must allow renegotiation. The audit is how renegotiation happens.

- The companion MUST expose a user-initiated audit surface: inspect, correct, delete, and prune the model the companion holds.
- The user — not the platform — MUST be the party that triggers advancement through trust phases (training wheels → hands off → open road).
- Without this, the vault is yours and the companion guards it, but the model inside drifts from who you are with no way to call it back. The audit closes that gap.

### 7.9 Privacy-preserving reasoning

The companion's reasoning MAY run on cloud compute, but the data it reasons from MUST NOT leave the vault in a form the operator can retain, aggregate, or sell. Conformant techniques include:

- **Federated learning** — personalization updates computed on-device; only the learned update moves, never the underlying data.
- **Homomorphic encryption** — the companion queries the vault over encrypted data and receives an answer without the contents being exposed in readable form.
- **Zero-knowledge architectures** — the operator runs the reasoning without being able to access the inputs.

A companion that requires user data to reside on its operator's servers in operator-usable form is **not** conformant — it is the extraction architecture with a friendlier name. The Replika enforcement action (Italy, 2025) is the documented failure mode of omitting this clause.

---

## 8. Threat Model

### 8.1 In scope

| Adversary | Goal | Mitigation |
|---|---|---|
| Curious/compromised server operator | Reconstruct social graph | P2: deposit/drain unlinkable by construction (§4); operator never holds linkage |
| Server operator | Read content | All payloads E2E-encrypted; server stores opaque bytes (§4.2) |
| Identity thief | Forge/guess a Quad-Key | 128-bit entropy floor + Argon2id memory-hardness (§3.4); unknown factor composition widens & randomizes attack surface (§3.2) |
| Coercion / device seizure | Force account disclosure | Duress identity (§3.7); device-agnostic, no local persistence (§6.3) |
| Future key compromise | Decrypt history | Double Ratchet forward secrecy (§6.2) |
| Spam/flood | Drown the user | Lobby filtering replaces sender-ID (§5.2); flooding reaches nothing past the filter |
| Malicious node | Degrade service | Federation: a bad node still can't read content or build the graph (§9); it can only go offline or throttle |
| Operator/advertiser bribery (vault) | Buy access to the vault | P3: no revenue model rewards granting access (§7.2) |

### 8.2 Recovery as a user-chosen tradeoff

The variable-input Quad-Key turns recoverability from a structural inevitability into a design choice. Passphrase-only → forgetting the words means permanent loss. Adding a hardware token (storable in a second location), a social-recovery contact, a persistent biometric, or a re-attestable SSI credential adds recovery paths. **The user owns this tradeoff; the protocol MUST NOT impose it either way.**

### 8.3 Honestly-named limitations

These are properties of *this* protocol, not of the sovereignty principles — different applications will trade differently:

- **Polling vs. push.** The dead-drop trades real-time delivery for metadata privacy. Polling is less efficient; for most uses acceptable, for time-critical ones a constraint.
- **Federation distributes reliability, not just trust.** A node can't read content or build the graph, but it can go offline, throttle, or impose retention policies. Federation is a security property, not a reliability guarantee.
- **Biometric factors can't be rotated.** If a biometric hash leaks, it's compromised forever — hence "one factor among several," never sole.

### 8.4 Out of scope (MUST be handled by the deployment)

- **Network-layer correlation.** IP/timing correlation is outside the cryptographic guarantees. Senders SHOULD use Tor or a mixnet (§4.2). The protocol does not provide this itself.
- **Endpoint compromise.** A compromised device defeats everything; client integrity is the deployment's responsibility.
- **Coerced live unlock without duress key configured.** Duress mode mitigates only if set up in advance.
- **Quad-Key entropy supplied by the user.** The protocol enforces a floor but cannot make a user choose good factors; onboarding UX carries this burden.

---

## 9. Deployment & Sustainability

GhostBox collects no data, so it cannot be funded by advertising or behavioral monetization (which is the point — **P3**). Viable models:

- **Community hosting.** Server software is open source; anyone can run a GhostBox Node, federated like a Mastodon instance, with no central point of control or failure.
- **Freemium.** Free tier = 24-hour TTL (§4.4). Paid tiers (via privacy-preserving payment) = extended retention, larger transfers, priority bandwidth.
- **Enterprise licensing.** Private deployments where the confidentiality of the *communication pattern* matters as much as content: legal teams, investigative journalists, civil-society orgs, medical practices.

Node operator requirements:

- A node MUST NOT log deposit↔drain linkage, sender IP against deposits, or any data enabling graph reconstruction (§4).
- A node MUST publish its retention policy and MUST honor advertised TTLs.
- A node SHOULD publish a reproducible build hash so clients can verify the code it runs matches the audited source (**P4**).

---

## 10. Conformance

An implementation MAY claim one or both conformance levels.

**Level 1 — GhostBox Transport.** Satisfies every MUST in §3 (Spirit), §4 (Specter), §5 (Corporeal), §6 (Crypto), and the node requirements in §9.

**Level 2 — Sovereign Companion Deployment.** Satisfies Level 1 **and** every MUST in §7 (Permissions Layer).

A conformance claim MUST state the level, the Argon2id parameter versions supported, and any §8.4 out-of-scope items the deployment does or does not address.

---

## 11. Glossary

| Term | Meaning |
|---|---|
| Spectre Stack | The three-layer GhostBox architecture: Spirit, Specter, Corporeal |
| Spirit Layer | Identity layer; invisible, derived, never server-held |
| Specter Layer | Transport layer; passive dead-drop that cannot link sender to recipient |
| Corporeal Layer | Discovery layer; voluntary presence + relationship-state model |
| Quad-Key | Composite of ≥4 high-entropy factors that derives identity |
| Locator Hash | Public Drop-Box address; deposit-only |
| Access Token | Private credential; signs retrieval, derives content keys; never sent to server |
| Drop-Box | Storage location addressed by a Locator Hash |
| Lobby | Tier-1 filtering Drop-Box for inbound connection requests |
| Ghost Channel | Tier-2 per-relationship private channel |
| Public Mask | Voluntary DHT-listed alias pointing to a Lobby |
| Proximity handshake | Discovery via shared physical context; strongest privacy mode |
| Five-state model | Stranger · Acquaintance · Preliminary · Established · Revoked |
| Duress Quad-Key | Secondary key opening a plausible empty account under coercion |
| Access matrix | Companion's map of external parties → relationship state + scope |
| Companion | AI gatekeeper between the vault and the world; non-bribable by construction |
| Vault | User-owned personal data store (out of scope here) |

---

*Sovereign Communication & Permissions Specification v0.1.0 — draft for open review.*
*Architecture by Cory A. Ottenwess. Companion text: Notes from an Acceleration Native.*
