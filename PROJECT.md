# GhostBox Protocol — Project Reference

*The complete rundown: what this is, why it exists, what it does, and how to work on it without breaking it. Read this first in any session.*

**Protocol version:** 0.4.0
**Repository:** `github.com/cottenwess/sovereign-comms`
**License:** AGPL-3.0-or-later
**Companion text:** *Notes from an Acceleration Native* (Appendix B, Chapter 11)
**Author:** Cory A. Ottenwess

---

## 1. North Star

**Remove the intermediary's access, instead of asking for its restraint.**

Every dominant communication and personal-data platform shares one structure: an operator sits between people and monetizes the position. The social graph, the message stream, and the behavioral record are the assets, and no privacy policy changes who holds them. The standard defense is a promise about behavior, and a promise is worth exactly the incentive to keep it — which runs the other way when the revenue model rewards access.

GhostBox answers a different question. Not *"will this operator behave?"* but *"does the architecture make misbehavior possible at all?"* The whole project is the work of making "no" the true answer at the level of cryptography and economics rather than policy. If the operator cannot see the graph, cannot read the content, and cannot reach the vault, there is nothing to promise about, because there is nothing to misuse.

This is deliberately an **architectural** argument, not an adversarial one. The aim is not to defeat platforms in a contest. It is to build infrastructure where the contested resource — comprehensive access — never accumulates in one place to begin with, and to name that architecture precisely before the current one hardens.

---

## 2. What It Is

Two interlocking pieces of sovereignty infrastructure, specified together because they apply one design decision at two layers:

**The GhostBox Protocol** — a zero-identity, asynchronous, dead-drop communication protocol. Two parties exchange messages without the transport ever learning who is talking to whom.

**The Companion Permissions Layer** — the access-control model between a personal data vault and the outside world, mediated by an AI companion that acts as a non-bribable gatekeeper. (Specified; not the focus of the current reference implementation.)

The shared decision: *remove the intermediary's ability to extract value from a user's data by removing the intermediary's access to that data.* GhostBox applies it to message transport; the Permissions Layer applies it to vault access.

---

## 3. The Six Design Principles

Every requirement traces back to one of these. Every tradeoff is resolved in their favor.

1. **Possession is identity.** Identity is derived by the user from secrets and factors they hold — no registration, no server-held account. Nothing for a platform to revoke, suspend, or sell.
2. **The server cannot build the graph.** The transport is structurally incapable of linking sender to recipient. A mathematical property, not a policy promise.
3. **Extraction incentive absent by construction.** No component that mediates access to user data has a financial relationship with parties seeking that data. The gatekeeper cannot be bribed because the revenue model that would reward it does not exist.
4. **Trust is verifiable, not declared.** Every component handling user data is auditable: open code, public governance, behavior checkable against the spec. *(This principle is why the repository is the way it is — see §7.)*
5. **Presence mirrors social reality.** The relationship model represents the full gradient of human connection, not a connected-or-not binary. Access is scoped, revocable, user-defined at every stage.
6. **The user decides; the companion holds.** The companion never advances trust, widens access, or alters a permission on its own authority. It holds the shape of what the user decided, flags when that shape may need revisiting, and waits.

---

## 4. Architecture — the Spectre Stack

Three independent layers. Independence is a hard requirement: compromise of one MUST NOT compromise another. The layers move from invisible and private, through passive and unlinkable, to voluntary and present.

**Spirit Layer — Identity.** Invisible; exists only in user memory and transient RAM. A Quad-Key (four or more high-entropy factors the user holds) passes through measured entropy enforcement and a memory-hard derivation into a public Locator Hash and a private Access Token. No server holds it. It cannot be seized (no physical location) or revoked (no administrator).

**Specter Layer — Transport.** A passive dead-drop. Deposit an encrypted blob at a Locator Hash; drain it by challenge-response; time-limited storage. The server stores opaque bytes and cannot link deposit to drain. *This is Principle 2 realized as plumbing.*

**Corporeal Layer — Discovery.** Voluntary presence on the user's terms. Public Mask, Lobby, and Ghost Channel components; four discovery modes (public alias, proximity handshake, mediated introduction, relayed social connection); all governed by the five-state relationship model (Stranger → Acquaintance → Preliminary → Established → Revoked).

The **Companion Permissions Layer** is not part of the stack — it consumes it, using the Corporeal relationship model as its vocabulary for vault access control and the Specter Layer as its transport.

---

## 5. What It Does — Reference Implementation Status (v0.4.0)

The repository is a **readable reference**, not a hardened or audited library. What is actually built and tested:

| Component | File | Status |
|---|---|---|
| **Spirit Layer — identity derivation** | `src/identity.ts` (canonical), `reference/identity.py` | **Built.** Measured zxcvbn entropy, per-class caps, diversity rule, full RFC 5869 HKDF salts, Argon2id ladder, keypair derivation. Cross-language byte-identical, verified by frozen vectors. |
| **Specter Layer — dead-drop transport** | `src/transport.ts` | **Built.** Sealed-box (ephemeral-static X25519 + XChaCha20-Poly1305) for the pre-session Lobby flow, the passive drop server, challenge-response retrieval, TTL purge — and, as of v0.4.0, `RatchetSession`: the forward-secret in-channel path with a transactional (anti-DoS) receive. |
| **Key commitment (UtC envelope)** | `src/envelope.ts` | **Built.** Committing AEAD defending the Invisible Salamanders / partitioning attack; wired into seal/unseal. |
| **Symmetric ratchet (forward secrecy)** | `src/ratchet.ts` | **Built and wired (v0.4.0).** Triple-DH handshake → shared root, per-direction KDF chains, 64-key skip cap. Message keys route through the committing envelope with the message-number header as authenticated AD (`RatchetSession`); state serializes into the §6.4 sync channel. Exercised end-to-end by `test-vectors/fs-transport.mts`. |
| **State-sync derivation** | `src/statesync.ts` | **Built (v0.4.0).** Sync address + forward-ratcheted key ladder, and canonical byte-stable ratchet-state serialization (imports the real `RatchetState`; strict deserialization rejects malformed/non-canonical encodings). Wipe-and-restore through the sync channel tested in anger. |
| **AT Protocol bridge** | `src/atproto-bridge.ts`, `lexicons/com.ghostbox.identity.json` | **Built.** Publish/resolve a GhostBox address via an AT Proto identity. Logic verified offline; live network is the user's step. |
| **Browser demo** | `demo/index.html` | **Built.** Runs the dead-drop client-side; shows the server holds no social graph. |

**CI:** ten jobs, all green from a clean `npm ci` — typecheck, vectors-TS, vectors-PY, integration, atproto-bridge, key-commitment, state-sync, ratchet, fs-transport, unlinkability.

---

## 6. Honestly-Named Limitations

Stating these is itself Principle 4. They are properties of the design, named plainly.

- **Application-layer unlinkability only.** The protocol's data structures don't encode the social graph, but network-layer correlation (IP/timing) is out of scope and needs Tor or a mixnet.
- **Forward secrecy is in-channel only, and unreviewed.** `RatchetSession` (v0.4.0) gives forward secrecy for Ghost Channel conversation; the sealed-box Lobby path deliberately remains sender-anonymous-but-not-forward-secret. None of it has had independent cryptographic review yet (roadmap #1).
- **Symmetric ratchet, not a DH ratchet.** No session-level post-compromise security — deliberate, since identity compromise is permanent by design.
- **Not audited.** Tests passing is not a cryptographer's review. Nothing here should be relied on for safety until independently audited.
- **Polling, not push.** Metadata privacy is bought with delivery latency.
- **Biometric factors cannot be rotated.** A leaked biometric hash is compromised forever — hence one factor among several, never sole.
- **The AT Proto bridge publishes a public locator.** Discoverability costs the anonymity of the address itself; wrong for hiding presence (see the bridge's privacy note).

---

## 7. Working On This Without Breaking It

**The history that makes this section necessary:** v0.3.1 exists because earlier work was layered onto a stale baseline. The TypeScript identity module used full HKDF while the Python reference and frozen vectors used bare HMAC — so the two languages derived *different identities* while CI stayed green, because the checkers reimplemented the logic instead of importing the real modules. The fix regenerated everything from the real modules and made the checkers import, not reimplement. Do not let this recur.

**Session-open protocol (do this in order, every time):**

1. **Verify the baseline.** Run `node verify_manifest.mjs`. It recomputes SHA-256 for every tracked file against `MANIFEST.json`. CLEAN = safe to build. DRIFT = your working copy differs from the recorded v0.3.1 baseline; reconcile before doing anything else.
2. **Read this file and `SPECIFICATION.md`.** The spec is normative; this file is orientation.
3. **Confirm CI is green** on the live repo before extending.
4. **Build. Then regenerate the manifest** (`node make_manifest.mjs` — or the inline generator) and re-run the suite from a clean `npm ci`.

**Non-negotiable rules:**

- **Checkers import the real modules. They never reimplement derivation.** This is the rule that would have prevented the original bug.
- **Cross-language parity is verified by running both modules, not by reasoning.** If TS and Python must agree, a test runs both and compares bytes.
- **Regenerate frozen vectors from the real modules** whenever a construction changes. Never freeze on top of an uncorrected construction.
- **Keep `package-lock.json` committed.** `npm ci` fails without it.
- **The repo governs for implementers; the book is illustration.** Appendix B's code intentionally diverges (per-composite salts, versioned Argon2id). Do not reconcile them.
- **noble is on the 2.x line.** Import paths use `.js` subpaths (`@noble/hashes/hkdf.js`), and `hkdf` `info` must be a `Uint8Array`, not a string.

---

## 8. Key Terminology

**Spectre Stack** — the three-layer architecture (Spirit / Specter / Corporeal). **Quad-Key** — composite of four or more high-entropy user-held factors. **Locator Hash** — public 16-byte deposit-only Drop-Box address. **Access Token** — private 32-byte seed; authorizes draining and seeds the keypairs. **Lobby** — disposable Tier-1 filtering address for inbound requests. **Ghost Channel** — per-relationship Tier-2 address, independently keyed. **Duress identity** — secondary Quad-Key deriving a plausibly-innocuous decoy. **Companion** — the non-bribable agent mediating vault access. **UtC envelope** — the committing-AEAD message wrapper. **Five-state model** — Stranger, Acquaintance, Preliminary, Established, Revoked.

---

## 9. Roadmap (open work, in rough priority)

1. **Independent cryptographic review** — the ratchet construction, the triple-DH root, AND the v0.4.0 wiring (RatchetSession, transactional receive, state serialization), before anyone relies on forward secrecy. *(Was #2; #1 — wire the ratchet into transport + sync — landed in v0.4.0.)*
2. **Corporeal Layer reference** — the discovery handshake and five-state model in code. The `establishSession` seam in `src/transport.ts` is where the Lobby ephemeral exchange plugs in.
3. **Wire-format spec** — byte-level message format so an independent implementation can interoperate (the session-blob and ratchet-state layouts from v0.4.0 are the starting material).
4. **Update the v0.1.0 PDFs to current** — the designed white paper and technical reference still lag the repo.
5. **Companion Permissions Layer reference** — the second pillar.

---

*This document is maintained alongside the code. When the protocol version changes, update §1's version stamp, §5's status table, and regenerate `MANIFEST.json`.*
