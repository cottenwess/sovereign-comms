# Sovereign Communication & Permissions

> Communication and access-control infrastructure where the intermediary **cannot** extract your data — not because it promises not to, but because the architecture never gives it the ability.

This repository contains the open specification and reference implementation for two interlocking pieces of sovereignty infrastructure:

- **The GhostBox Protocol** — a zero-identity, asynchronous, dead-drop communication protocol. Two parties exchange messages and assets without the transport infrastructure ever learning who is talking to whom.
- **The Companion Permissions Layer** — the access-control model between a user's personal data vault and the outside world, mediated by an AI companion that acts as a non-bribable gatekeeper.

Both apply one design decision at two layers: **remove the intermediary's ability to extract value from your data by removing its access to that data.**

---

## Status

**v0.1.0 — working draft.** The specification is complete and open for review. The reference implementation covers the Spirit Layer (identity derivation) and is intended to be read alongside the spec, not deployed as-is. This is infrastructure for review and contribution, not a finished product. See [the spec's honestly-named limitations](./SPECIFICATION.md#83-honestly-named-limitations) before building anything on it.

## Start here

| If you want to... | Read |
|---|---|
| Understand the whole design | [`SPECIFICATION.md`](./SPECIFICATION.md) |
| See the principles in one screen | [Design Principles](./SPECIFICATION.md#1-design-principles) |
| Understand the threat model | [§8 Threat Model](./SPECIFICATION.md#8-threat-model) |
| Build a client | [`src/`](./src) (TypeScript, canonical) |
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

## License

[GNU AGPLv3](./LICENSE). Chosen deliberately. This project's whole argument is that infrastructure should make extraction *structurally* impossible rather than relying on good intentions — so a permissive license that lets a hosted fork quietly add metadata logging and never publish the change would contradict the thesis. The AGPL's network-use clause closes that loophole: anyone who runs a modified version as a service **must** publish their source, which is what makes Principle 4 (verifiability) enforceable rather than aspirational.

If you need different terms for a specific use, open an issue to discuss.

## Provenance

Architecture by **Cory A. Ottenwess**. Companion text: *Notes from an Acceleration Native* (Appendix B and Chapter 11). This repository is the implementation reference; the book is the argument for why it should exist.
