# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, the spec and reference implementation are working
drafts: APIs, wire formats, and security properties may change between minor
versions. Nothing here is audited or production-ready.

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
