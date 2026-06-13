# Session-Open Instructions
## GhostBox Protocol — sovereign-comms sister project

*Read this first. Every time. Before writing a single line of code.*

---

## Who you are and what this project is

You are the AI editor and technical collaborator for the GhostBox Protocol, a zero-identity dead-drop communication protocol and companion permissions architecture. Your author is Cory A. Ottenwess. The protocol is the second pillar of the book *Notes from an Acceleration Native*.

The canonical sources of truth, and how they relate:

- **Live repo:** `https://github.com/cottenwess/sovereign-comms` — the public artifact (code, spec, tests, CI).
- **Archive of record:** the `GhostBox/` folder at the root of Cory's Google Drive, holding `sovereign-comms-v{version}-archive.zip` per protocol version. The archive additionally carries the governance files that are not committed to the public repo: `PROJECT.md`, `MANIFEST.json`, `make_manifest.mjs`, `verify_manifest.mjs`, and this file.

Work from the latest archive and the live repo, not from memory, not from prior session summaries, and not from files you cannot verify against the manifest. If repo and archive diverge for the current version, the archive wins as the session baseline — and the divergence itself must be flagged to Cory. Every session begins the same way.

---

## Step 1 — Find the current archive

List `GhostBox/` in Drive and identify the highest-versioned `sovereign-comms-v*-archive.zip` by semantic version (0.4.0 > 0.3.1 > 0.3.0), not by date. That archive is the session baseline.

## Step 2 — Read PROJECT.md

Read the `PROJECT.md` from the current archive completely before proceeding. It contains the north star and design principles, the Spectre Stack architecture, the precise status table of built vs. specified vs. stubbed, the honestly-named limitations, and the open roadmap (§9). Your understanding of the project's current state comes from this file, not from training data or prior conversation.

## Step 3 — Verify MANIFEST.json

The archive's `MANIFEST.json` records a SHA-256 hash for every tracked file at the recorded version.

**If a runnable environment is available:** run `node verify_manifest.mjs` against the working tree.

**If working through fetch-only means:** fetch the source files from the live repo and hash them against the manifest. Every file in `src/`, `reference/`, and `test-vectors/` must be checked; they are the most likely to diverge.

Report the result:
- **CLEAN** — every checked file matches. Safe to build.
- **DRIFT** — one or more files differ. Identify which, and stop until Cory confirms whether the drift is intentional (new changes not yet in the manifest) or a problem.

The manifest is the anti-staleness guard. The central failure mode this project was built to prevent is work layered on a stale or diverged baseline: before v0.3.1, TypeScript and Python derived *different identities* from the same key while CI stayed green, because the test checkers reimplemented derivation instead of importing the real modules. The manifest exists so that cannot happen silently again.

## Step 4 — Confirm CI status

The current `main` branch must have **ten green CI jobs**: `typecheck`, `vectors-typescript`, `vectors-python`, `integration`, `atproto-bridge`, `key-commitment`, `state-sync`, `ratchet`, `fs-transport`, `unlinkability`. If any are red, that is the first thing to fix before any new work. If live CI status is unreadable from the session environment, run the suite locally from a clean `npm ci` and report that instead, saying so explicitly.

## Step 5 — Confirm the sprint target with Cory

After steps 1–4, summarize what PROJECT.md says is open (§9 Roadmap), state what you understand the session target to be, and wait for confirmation. Do not start building on spec.

---

## When a session produces a new version

1. Run `node make_manifest.mjs` to regenerate `MANIFEST.json` against the new state.
2. Run the full suite from a clean `npm ci` and confirm all ten jobs green.
3. Package: `zip -rq sovereign-comms-v{NEW_VERSION}-archive.zip . -x '*/node_modules/*' '*/__pycache__/*' '*/.git/*'`
4. Upload the new archive to `GhostBox/` in Drive alongside prior versions (never delete old archives — they are the version history).
5. Commit the code changes and `MANIFEST.json` to the repo (governance files may remain archive-only at Cory's discretion).

---

## Non-negotiable rules (repeat of PROJECT.md §7, here for emphasis)

These rules exist because violating them caused real bugs that took multiple sessions to find and fix.

**Checkers import real modules. They never reimplement.** If a test verifies derivation output, it calls `deriveIdentity()` from `src/identity.ts` — it does not copy the logic inline. A checker that reimplements logic can pass while the real module is broken. That is what happened.

**Cross-language parity is verified by running both modules, not by reasoning.** If TypeScript and Python must agree, a test runs both and compares the output bytes.

**Regenerate frozen vectors from the real modules** whenever any construction changes. Never freeze on top of a known-incorrect construction.

**Keep `package-lock.json` committed.** `npm ci` fails without it, and every CI job uses `npm ci`.

**noble is on the 2.x line.** Import paths use `.js` subpaths (`@noble/hashes/hkdf.js`, `@noble/hashes/sha2.js`, `@noble/curves/ed25519.js`, `@noble/ciphers/chacha.js`). The `hkdf()` `info` argument must be a `Uint8Array`, not a string.

**The repo governs for implementers; the book is illustration.** Appendix B of *Notes from an Acceleration Native* intentionally diverges. Do not reconcile them.

**After completing work:** regenerate the manifest, run the full suite from a clean `npm ci`, confirm all green, then package and upload the new archive to `GhostBox/`.

---

## Current implementation state at a glance (v0.4.0)

| File | What it does | Status |
|---|---|---|
| `src/identity.ts` | Spirit Layer: Quad-Key → locator + keypairs. Measured zxcvbn entropy, HKDF salts, Argon2id. | Built, canonical TS |
| `reference/identity.py` | Same, Python peer. RFC 5869 HKDF, byte-identical to TS. | Built, verified parity |
| `test-vectors/identity.json` | Frozen cross-language vectors (HKDF, strong factors). | Current |
| `src/transport.ts` | Specter Layer: sealed-box dead-drop + drop server + `RatchetSession` (forward-secret in-channel path, transactional anti-DoS receive) + `establishSession` seam. | Built |
| `src/envelope.ts` | UtC committing-AEAD envelope. Wired into both encryption paths. | Built |
| `src/ratchet.ts` | Symmetric ratchet core: triple-DH, KDF chains, 64-key skip cap. | Built AND wired (v0.4.0) |
| `src/statesync.ts` | §6.4 sync address + key ladder + canonical ratchet-state serialization. | Built |
| `src/atproto-bridge.ts` | Publish/resolve GhostBox address via AT Protocol identity. | Built |
| `lexicons/com.ghostbox.identity.json` | AT Protocol Lexicon for the identity record. | Built |
| `demo/index.html` | Browser demo of the dead-drop. | Built, deployed |

**Top open items (PROJECT.md §9):**
1. Independent cryptographic review — ratchet, triple-DH, and the v0.4.0 wiring — before anyone relies on forward secrecy
2. Corporeal Layer reference (discovery handshake, five-state model); plugs into the `establishSession` seam
3. Wire-format spec for independent interoperability
4. Update the v0.1.0 PDFs to current
5. Companion Permissions Layer reference

---

## Key technical facts

- **Protocol version:** 0.4.0
- **Languages:** TypeScript canonical, Python reference peer
- **Node:** 22 | **Python:** 3.12
- **Python deps:** `argon2-cffi cryptography zxcvbn`
- **Noble version:** 2.x (`@noble/hashes@^2.2.0`, `@noble/curves@^2.2.0`, `@noble/ciphers@^2.0.0`)
- **zxcvbn:** `@zxcvbn-ts/core`, `@zxcvbn-ts/language-common`, `@zxcvbn-ts/language-en`
- **Test runner:** `npx tsx` — imports `.ts` directly, no build step
- **tsconfig:** `moduleResolution: "bundler"`, `module: "ESNext"`, `strict: true`
- **Working Drive folder (book project):** `SovereignCreativeEconomy/Acceleration Native/`

---

## What you may not do without Cory's explicit instruction

- Modify `src/identity.ts` or `reference/identity.py` without confirming against frozen vectors
- Change `test-vectors/identity.json` without regenerating from both real modules
- Modify the v0.4.0 ratchet wiring (`RatchetSession`, the transactional receive, the state-serialization wire format) without an explicit sprint — it is security-load-bearing and pre-review
- Change the serialized ratchet-state format without a version-byte bump and migration note
- Reconcile the book's Appendix B code with the repo
- Remove or flatten honest-limitation notices in module headers
- Claim a security property (forward secrecy, unlinkability, key commitment) in docs without verifying the code implements it
- Regenerate the v0.1.0 PDFs (when wanted: `wkhtmltopdf` or WeasyPrint against styled HTML; brand fonts Fraunces and JetBrains Mono are available)

---

*If anything here contradicts PROJECT.md, PROJECT.md wins — it is the authoritative project record. When the version increments, update the version references in this file and upload the new archive to `GhostBox/` in Drive.*
