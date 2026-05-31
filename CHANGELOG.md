# Changelog

All notable changes to the GhostBox Protocol specification and reference
implementation are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once past
the working-draft stage.

> **Cutting a release:** to tag the corrections below as `0.1.1`, rename the
> `[Unreleased]` heading to `[0.1.1] - YYYY-MM-DD` and start a fresh
> `[Unreleased]` section above it.

## [Unreleased]

Specification and reference-implementation corrections following two external
architectural reviews. No change in this set alters the Spirit-Layer derivation
math; the corrections either tighten it, document it accurately, or add
requirements to layers the reference code does not yet implement.

### Added

- **§6.1.1 Key commitment (committing AEAD).** All AEAD operations MUST now be
  wrapped in the UtC (UNAE-then-Commit) transform, achieving CMT-4 commitment
  over key, nonce, and associated data. Neutralizes the Invisible Salamanders /
  partitioning-oracle attack, which otherwise lets a Mediated-Introduction
  party present different plaintext to two recipients under one ciphertext.
- **§6.4 Asynchronous state synchronization.** Resolves the Double Ratchet
  statefulness paradox under wipe-on-exit. Encrypted ratchet state is delegated
  to a dedicated derived address (`sync_locator`) under a **forward-ratcheted**
  backup key, so a leaked session key cannot decrypt other sessions' state and
  the server stays passive. Documents the honest boundary: this does not provide
  post-compromise security against capture of the live Quad-Key.
- **§6.5.1 Sender-side read-receipt timing defense (Careless Whisper).** Read
  receipts MUST NOT transmit automatically; transmission is gated on an explicit
  user action, jittered, and batchable, and clients SHOULD NOT expose derived
  real-time signals. Closes the covert-ping telemetry channel against a
  malicious sender.
- **§8.3 design note** on planned anonymous Lobby rate-limiting via
  recipient-issued tokens (Privacy Pass / VOPRF). Records why Proof-of-Work and
  staked ZK Rate-Limiting Nullifiers were considered and rejected (battery
  regressiveness; reintroduction of a persistent on-chain identity).
- **Threat model (§8.1)** row for the malicious-sender receipt-telemetry
  adversary.
- **Test vectors** regenerated from the corrected derivation, with per-language
  conformance checkers (`verify_vectors.py`, `verify_vectors.mjs`) wired into CI.

### Changed

- **§3.3 Salt derivation** corrected to full RFC 5869 HKDF (Extract **then**
  Expand) with the composite as IKM, an empty salt, and the domain label as
  `info`. The earlier illustration showed a single `HMAC(label, composite)`
  (Extract only), which is not HKDF and breaks cross-implementation parity.
- **§3.2 Entropy enforcement** specified concretely: entropy is **measured**
  (zxcvbn for `know` factors), never accepted as a caller-declared value;
  per-class caps and a diversity rule are now normative.
- **§0.4** now lists three divergences from the book (static→per-composite salt,
  single→versioned Argon2id ladder, and the HKDF Extract-then-Expand correction).
- **§6.2 / §6.3** reconciled so forward secrecy and wipe-on-exit no longer read
  as contradictory; both point to the §6.4 state-sync mechanism.
- **§6.6 reference snippet** rewritten to match the corrected construction
  (real HKDF, measured entropy, `finally`-block wipe, keypair derivation).
- **§8.1 spam/flood** mitigation stated honestly: filtering protects attention
  and channels, not bandwidth; a flood still imposes client-side drain/decrypt.

### Fixed

- **Cross-language parity.** The Python reference derived its per-composite salt
  with a bare `HMAC(label, composite)` while the canonical TypeScript used real
  RFC 5869 HKDF, so the two produced different identities from the same Quad-Key.
  Python corrected to match TypeScript byte-for-byte.
- **Entropy floor trust boundary.** The floor previously trusted a
  caller-supplied entropy figure; it is now measured inside the identity layer,
  closing the gap where a caller could assert a passing score for a weak key.

### Security

- **Entropy caps and diversity.** Per-class caps (`know` 80, `are` 24, `have` 64,
  `who` 64 bits) and the rule that no single factor may supply more than half the
  128-bit floor, forcing genuine multi-factor composition. The `are` cap is
  deliberately hard-low because biometric factors are non-revocable.
- **Memory hygiene.** The composite is zeroed in a `finally` block so a mid-
  derivation error cannot skip the wipe. The managed-runtime erasure ceiling
  (immutable strings cannot be wiped) is documented in `SECURITY.md` rather than
  papered over.
- **Mandatory key commitment** for all AEAD (see Added, §6.1.1).

### Notes

- The reference implementation remains **Spirit-Layer only** and is illustrative,
  not a hardened library; it has not been independently audited.
- The repository's reference code intentionally diverges from the book's
  Appendix B (per-composite HKDF salts, versioned Argon2id). For implementers the
  repository governs; the book is accurate as illustration.

## [0.1.0] - 2026-05

Initial public working draft.

### Added

- `SPECIFICATION.md`: the full GhostBox Protocol (Spirit / Specter / Corporeal
  layers) and the Companion Permissions Layer.
- White paper and technical reference (PDF).
- Reference implementation of Spirit-Layer identity derivation: canonical
  TypeScript (`src/identity.ts`) and Python reference (`reference/identity.py`).
- Cross-language test vectors and `SECURITY.md`.
- AGPL-3.0-or-later license.

[Unreleased]: https://github.com/cottenwess/sovereign-comms/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cottenwess/sovereign-comms/releases/tag/v0.1.0
