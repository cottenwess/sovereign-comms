# Sovereign Communication & Permissions

> Communication and access-control infrastructure where the intermediary **cannot** extract your data — not because it promises not to, but because the architecture never gives it the ability.

This repository contains the open specification and reference implementation for two interlocking pieces of sovereignty infrastructure:

- **The GhostBox Protocol** — a zero-identity, asynchronous, dead-drop communication protocol. Two parties exchange messages and assets without the transport infrastructure ever learning who is talking to whom.
- **The Companion Permissions Layer** — the access-control model between a user's personal data vault and the outside world, mediated by an AI companion that acts as a non-bribable gatekeeper.

Both apply one design decision at two layers: **remove the intermediary's ability to extract value from your data by removing its access to that data.**

---

## Status

**v0.3.0 — working draft.** The reference implementation covers the **Spirit Layer** (identity derivation, `src/identity.ts`), the **Specter Layer** (the dead-drop transport, `src/transport.ts`), and an **AT Protocol bridge** (`src/atproto-bridge.ts`) that lets an AT Proto / Bluesky identity publish and resolve a GhostBox address — public identity from AT Proto, private transport from GhostBox. An end-to-end integration test drives the transport with real derived identities; a runnable demonstration (`test-vectors/verify_unlinkability.mjs`) shows by inspection that the server's complete state contains no sender→recipient social graph; and an offline bridge test (`test-vectors/atproto-bridge.mjs`) verifies the discovery→private-message flow with the network mocked.

Read the scope honestly: the unlinkability demonstration establishes **application-layer** unlinkability, not resistance to a network-layer adversary ([SPEC §8.4](./SPECIFICATION.md#84-out-of-scope-must-be-handled-by-the-deployment)); the transport reference uses sealed-box encryption, which gives sender anonymity but **not** the forward secrecy the spec calls for ([SPEC §6.2](./SPECIFICATION.md#62-forward-secrecy)); and the AT Proto bridge involves a deliberate **privacy tradeoff** — see below. This is infrastructure for review, not a finished or audited product.

Read the scope honestly before drawing conclusions: the unlinkability demonstration establishes **application-layer** unlinkability (the protocol's data structures don't encode who-talks-to-whom). It does **not** establish resistance to a network-layer adversary (IP/timing correlation — see [SPEC §8.4](./SPECIFICATION.md#84-out-of-scope-must-be-handled-by-the-deployment)), and the transport reference uses sealed-box encryption, which gives sender anonymity but **not** the forward secrecy the spec calls for ([SPEC §6.2](./SPECIFICATION.md#62-forward-secrecy)). This is infrastructure for review and contribution, not a finished or audited product. See [the spec's honestly-named limitations](./SPECIFICATION.md#83-honestly-named-limitations) before building anything on it.

## Start here

| If you want to... | Read |
|---|---|
| Understand the whole design | [`SPECIFICATION.md`](./SPECIFICATION.md) |
| See the principles in one screen | [Design Principles](./SPECIFICATION.md#1-design-principles) |
| Understand the threat model | [§8 Threat Model](./SPECIFICATION.md#8-threat-model) |
| Build a client | [`src/identity.ts`](./src/identity.ts) + [`src/transport.ts`](./src/transport.ts) (TypeScript, canonical) |
| See the unlinkability claim run | [`test-vectors/verify_unlinkability.mjs`](./test-vectors/verify_unlinkability.mjs) |
| Bridge an AT Proto / Bluesky identity | [`src/atproto-bridge.ts`](./src/atproto-bridge.ts) + [`lexicons/`](./lexicons) (see AT Protocol integration below) |
| Cross-check against the book | [`reference/`](./reference) (Python, illustrative) |
| Verify your implementation | [`test-vectors/`](./test-vectors) |
| Contribute | [`CONTRIBUTING.md`](./CONTRIBUTING.md) |

## The three layers (Spectre Stack)

```
CORPOREAL  (Discovery)  — voluntary presence; how parties find each other
SPECTER    (Transport)  — passive dead-drop; the server that cannot link
SPIRIT     (Identity)   — invisible; derived from a Quad-Key, never server-held
```

Each layer is independent: compromise of one must not compromise another.

## Design principles

1. **Possession is identity.** No registration, no account record, nothing for a platform to revoke or sell.
2. **The server cannot build the graph.** Sender-recipient unlinkability is a mathematical property, not a policy promise.
3. **Extraction incentive absent by construction.** The gatekeeper cannot be bribed because no revenue model rewards letting someone in.
4. **Trust is verifiable, not declared.** Open code, public governance, behavior checkable against the spec.
5. **Presence mirrors social reality.** A five-state relationship model, not a connected/not-connected binary.
6. **The user decides; the companion holds.** Nothing changes without user affirmation.

## A note on the canonical reference language

The book *Notes from an Acceleration Native* ships Python in its appendix. **This repository treats TypeScript as canonical** because identity derivation **must** run client-side in the user's browser/device (Principle 1) — Python can't satisfy that constraint without a server. The Python in [`reference/`](./reference) is kept as a faithful, illustrative companion so the two never drift. Where the original book code and this repository disagree, **this repository governs** — see [§0.4 of the spec](./SPECIFICATION.md#04-divergences-from-the-published-book-text) for the two deliberate corrections (per-composite salts; versioned Argon2id).

> ⚠️ **Argon2id is not native to browsers.** A conformant TypeScript client needs a WASM build of Argon2 (e.g. [`hash-wasm`](https://github.com/Daninet/hash-wasm)). Do **not** ship a pure-JS fallback — it will be too slow to use safe parameters and silently weakens every identity derived with it.

## AT Protocol integration

GhostBox and AT Protocol solve non-overlapping problems and compose cleanly. AT Proto answers *who is this person and how do I find them*; GhostBox answers *how do I talk to them privately*. The bridge ([`src/atproto-bridge.ts`](./src/atproto-bridge.ts)) lets an AT Proto identity publish a small public record — a GhostBox locator hash plus an X25519 key — so anyone who can resolve a handle (`@you.bsky.social` → DID → record) can discover a GhostBox address. The conversation itself then runs over the GhostBox dead-drop, encrypted and unlinkable, never touching the AT Proto network. Bluesky's own DMs are centralized and not end-to-end encrypted; this is the private layer the ecosystem doesn't have.

The record conforms to a published Lexicon, [`lexicons/com.ghostbox.identity.json`](./lexicons/com.ghostbox.identity.json), so any AT Proto client can read it. Resolution is `DID → DID document → PDS → getRecord → SendTarget`; the offline test mocks that chain and verifies a message addressed via a resolved identity round-trips through the dead-drop.

### ⚠️ The privacy tradeoff — read before publishing

Publishing a locator in a public AT Proto record makes the **association between your handle and your GhostBox address public and effectively permanent** — AT Proto repos are synced and archived via the firehose, so a published locator can persist in archives even after deletion. Message **contents** and the **social graph of who you message** stay private (the dead-drop still does its job). What becomes public is the *fact* that you use GhostBox, and *which* locator, bound to your real handle.

So the bridge is for the **findable** case — a creator or public figure who wants to be privately reachable. It is the **wrong** tool if your goal is that your very presence on GhostBox stay hidden; that is the Corporeal Layer's unlisted / proximity-only mode ([SPEC §5.4](./SPECIFICATION.md#54-discovery-mode-2--proximity-handshake)), which must not publish this record. Rotating to a fresh locator is the only mitigation once an association is public. **Do not publish a locator you need to keep secret.**

### Publishing your GhostBox identity

The bridge builds the records and resolves them; it does **not** handle your credentials (credentials never belong in library code). To publish, you run the authenticated write yourself:

1. Derive your GhostBox identity and take the public `locatorHash` (hex) and `encryptionPublic` (hex) from it.
2. Create an [App Password](https://bsky.app/settings/app-passwords) for your account.
3. Authenticate to your PDS (`com.atproto.server.createSession`) to get an access token.
4. `buildPutRecordRequest(pdsEndpoint, yourDid, buildIdentityRecord(locatorHex, encHex))` gives you the exact `com.atproto.repo.putRecord` endpoint and body. POST it with `Authorization: Bearer <accessJwt>`.

Once published, anyone can `resolveGhostBoxIdentity(yourDid)` to get a `SendTarget` and message you privately. (Note: `resolveGhostBoxIdentity` takes a DID; resolve a handle to a DID first via `com.atproto.identity.resolveHandle`.)

> **Verification status:** the bridge logic is typechecked against real types and verified offline against a mocked AT Proto network (`test-vectors/atproto-bridge.mjs`). The live network path — publishing to and resolving from a real PDS — is the step you run; it is not exercised in CI because it requires your credentials and live network access.

## License

[GNU AGPLv3](./LICENSE). Chosen deliberately. This project's whole argument is that infrastructure should make extraction *structurally* impossible rather than relying on good intentions — so a permissive license that lets a hosted fork quietly add metadata logging and never publish the change would contradict the thesis. The AGPL's network-use clause closes that loophole: anyone who runs a modified version as a service **must** publish their source, which is what makes Principle 4 (verifiability) enforceable rather than aspirational.

If you need different terms for a specific use, open an issue to discuss.

## Provenance

Architecture by **Cory A. Ottenwess**. Companion text: *Notes from an Acceleration Native* (Appendix B and Chapter 11). This repository is the implementation reference; the book is the argument for why it should exist.
