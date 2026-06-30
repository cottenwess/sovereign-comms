# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, the spec and reference implementation are working
drafts: APIs, wire formats, and security properties may change between minor
versions. Nothing here is audited or production-ready.

## [0.4.1] — 2026-06-28

Housekeeping release. No protocol, wire-format, or cryptographic behavior
changed from v0.4.0, and no source-file hash changed.

### Removed
- 19 duplicate source and test files that had accumulated at the repository
  root, shadowing their canonical homes under `src/`, `reference/`,
  `test-vectors/`, `demo/`, and `lexicons/`. They were byte-identical to the
  canonical files and imported by nothing (every CI job and every test resolves
  to the subdirectory paths), so removing them changes no behavior.

### Added
- `.gitignore` (standard Node and Python ignores).

## [0.4.0] — 2026-06-11

### Added
- **Forward-secret transport path** (`RatchetSession` in `src/transport.ts`).
  The §6.2 symmetric ratchet is now wired into the Specter Layer: per-message
  keys from `src/ratchet.ts` route through the committing envelope with the
  message-number header as authenticated associated data. One session per
  Ghost Channel; the channel address is the session selector, so blobs carry
  no sender tag and the server still cannot graph. Exercised end-to-end by
  `test-vectors/fs-transport.mts` (new CI job `fs-transport`, total now ten).
- **Ratchet-state serialization** (`src/statesync.ts`). The §6.4 stubs are
  replaced by a real canonical, byte-stable wire format for the live
  `RatchetState` (imported from `src/ratchet.ts`, not redefined); strict
  deserialization rejects malformed and non-canonical encodings. The full
  wipe-and-restore cycle through the sync channel is tested in anger.
- **`establishSession` seam** (`src/transport.ts`). The single point the
  future Corporeal-Layer Lobby handshake (§5.7) will plug into for ephemeral
  key exchange; until then callers supply the `HandshakeInput` out of band.

### Security
- **Transactional receive (anti-DoS).** Deposits are unauthenticated by
  design (§4.2), so `RatchetSession.openBlob` snapshots ratchet state and
  rolls back on any failure: forged headers and tampered blobs cannot burn
  message numbers, poison the skipped-key cache, or push a chain toward the
  MAX_SKIP cap. A tampered copy of a blob does not consume the original's
  message number.

### Changed
- The sealed-box path (`seal`/`unseal`) is unchanged and remains the right
  tool for the pre-session Lobby flow (sender anonymity); module headers,
  README, and SPEC reference notes updated to describe the two paths honestly.

## [0.3.1] — 2026-06-11

### Fixed
- **Cross-language identity parity.** TypeScript and Python derived different
  identities from the same Quad-Key while CI stayed green, because test
  checkers reimplemented derivation instead of importing the real modules.
  Both modules now agree byte-for-byte; frozen vectors regenerated from the
  real implementations; checkers import, never reimplement. `MANIFEST.json`
  introduced as the anti-staleness guard (entry backfilled — this release
  shipped without a changelog note).

## [0.3.0] — 2026-06-10

### Added
- **AT Protocol bridge** (`src/atproto-bridge.ts`). Connects an AT Protocol /
  Bluesky identity to GhostBox transport: publishes a public record (a GhostBox
  locator hash + X25519 key) so anyone who can resolve a handle can discover a
  GhostBox address, then resolves a DID to a `SendTarget` for private messaging.
  Public identity from AT Proto, private transport from GhostBox. This is the
  encrypted, unlinkable messaging the AT Protocol does not natively provide.
- **Lexicon schema** `lexicons/com.ghostbox.identity.json` defining the record
  type, so any AT Protocol client can read a GhostBox identity record.
- **Browser demo** (`demo/index.html`). Runs the real dead-drop client-side
  (X25519 + XChaCha20-Poly1305, no mockups): generate two identities, send
  messages, and watch the server's complete state show no sender→recipient
  social graph. Deployed at coryottenwess.com/notes/demo/.
- **Offline bridge test** (`test-vectors/atproto-bridge.mjs`) verifying the full
  discovery→private-message flow with the AT Protocol network mocked, plus a new
  CI job (`atproto-bridge`). CI now runs six jobs.

### Notes
- The AT Proto bridge involves a deliberate, documented privacy tradeoff:
  publishing a locator makes the association between a public handle and a
  GhostBox address public and effectively permanent (AT Proto repos are archived
  via the firehose). Message contents and the social graph of who you message
  stay private; the fact that you use GhostBox, and which locator, becomes
  public. The bridge is for the findable case, not for hiding your presence —
  see README "AT Protocol integration" and the unlisted/proximity mode in the
  spec.
- The live AT Proto network path (publishing to / resolving from a real PDS) is
  not exercised in CI: it needs credentials and live network access. Bridge
  logic is typechecked against real types and verified offline against a mocked
  network.

## [0.2.0] — 2026-05-28

### Added
- **Specter Layer reference** (`src/transport.ts`). The passive dead-drop
  transport: sender-anonymous sealed-box encryption (ephemeral-static X25519 +
  XChaCha20-Poly1305), the drop server (deposit / challenge-response retrieval /
  TTL purge), and client send/receive helpers. The protocol's central claim now
  runs in code.
- **End-to-end integration test** (`test-vectors/integration.mjs`) driving the
  transport with real derived identities, including negative cases (an imposter
  cannot drain another's mailbox; a third party cannot decrypt another's blob).
- **Unlinkability demonstration** (`test-vectors/verify_unlinkability.mjs`):
  runs a multi-party traffic pattern, then dumps the server's complete state and
  shows the sender→recipient social graph is not recoverable from it.
- CI jobs for the integration test and the unlinkability demonstration.

### Notes
- The unlinkability demonstration establishes application-layer unlinkability
  (the protocol's data structures do not encode who-talks-to-whom). It does not
  establish resistance to a network-layer adversary (IP/timing correlation),
  which requires Tor or a mixnet (SPEC §8.4).
- The transport reference uses sealed-box encryption, which provides sender
  anonymity but not the forward secrecy the spec calls for (Double Ratchet,
  SPEC §6.2). Documented gap.

## [0.1.0] — 2026-05-28

### Added
- Initial public release.
- **Unified specification** (`SPECIFICATION.md`) covering the GhostBox Protocol
  (Spirit / Specter / Corporeal layers) and the Companion Permissions Layer,
  with RFC-2119 requirement language, a threat model, and honestly-named
  limitations.
- **Spirit Layer reference**: identity derivation from a composite Quad-Key via
  per-composite HKDF salts and a versioned Argon2id parameter ladder, in
  TypeScript (canonical, `src/identity.ts`) and Python (`reference/identity.py`).
- **Frozen cross-language test vectors** (`test-vectors/`) with checkers in both
  languages, enforced in CI so the two implementations cannot silently diverge.
- **AGPLv3** license, **SECURITY.md** with private vulnerability reporting,
  **CONTRIBUTING.md**, and a committed lockfile for reproducible builds.

### Notes
- The reference code intentionally diverges from the book's Appendix B
  illustrative code (per-composite salts instead of static; versioned Argon2id).
  The repository governs for implementers; the book is fine as illustration.
- Reference implementations are readable demonstrations of correct construction,
  not hardened or independently audited libraries.

[0.3.0]: https://github.com/cottenwess/sovereign-comms/releases/tag/v0.3.0
[0.2.0]: https://github.com/cottenwess/sovereign-comms/releases/tag/v0.2.0
[0.1.0]: https://github.com/cottenwess/sovereign-comms/releases/tag/v0.1.0
