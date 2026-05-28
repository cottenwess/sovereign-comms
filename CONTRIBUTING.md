# Contributing

Thanks for considering a contribution. This project is infrastructure with real security stakes, so the bar for changes is deliberately high, and the process below exists to keep it that way — not to slow you down for its own sake.

## Before anything else

By contributing, you agree your contributions are licensed under the project's [AGPLv3](./LICENSE). Don't submit code you don't have the right to license this way.

## Ground rules specific to this project

1. **The specification is the source of truth.** Code follows `SPECIFICATION.md`. If you think the spec is wrong, change the spec first (in its own PR, with reasoning) — don't quietly diverge in code.
2. **Never weaken a cryptographic requirement to make something easier.** If a MUST in the spec is hard to satisfy, that is usually the point. Raise it as an issue; don't route around it.
3. **No pure-JS Argon2.** Identity derivation must use a WASM Argon2id build with the spec's parameters. A pure-JS fallback that runs "fast enough" is a security regression and will be rejected.
4. **No telemetry, ever.** This is non-negotiable. A PR that adds analytics, crash reporting that phones home, or any byte that leaves the device unbidden contradicts the entire project and will be closed.
5. **Salts are per-composite.** Static salts (as in the book's illustrative snippet) are a known divergence corrected in the spec (§3.3). Don't reintroduce them.

## What good contributions look like

- **Spec clarifications.** Ambiguity in a MUST/SHOULD, a missing edge case in the threat model, an under-specified wire sequence.
- **Test vectors.** More coverage in `test-vectors/` is always welcome — especially adversarial cases.
- **Reference completeness.** The Spirit Layer is implemented; the Specter and Corporeal layers need reference code that matches the spec exactly.
- **Independent review.** Found a flaw in the unlinkability argument or the duress-mode design? That's the most valuable PR you can file. Open an issue tagged `security` first (see below).

## Security issues

**Do not open a public issue or PR for a vulnerability.** Email the maintainer privately (see repository profile / book site) with:

- a description of the flaw,
- which spec section or file it affects,
- a proof-of-concept if you have one.

Give a reasonable window for a fix before public disclosure. Credit will be given unless you ask otherwise.

## Workflow

1. Open an issue describing the change before writing significant code, so we agree on direction.
2. Fork, branch from `main`, keep the change focused (one concern per PR).
3. If you touch derivation or transport, add or update test vectors.
4. Reference the relevant spec section in your PR description.
5. Expect review questions. Security-adjacent code gets read closely; that's a feature.

## Style

- TypeScript is canonical (`src/`); keep it strict-mode clean.
- Python in `reference/` exists to mirror the book and the spec — keep the two languages behaviorally identical and cross-checked against the same test vectors.
- Comment the *why*, not the *what*. The spec explains what; code should explain any non-obvious reason it's done a particular way.

## Conduct

Be direct, be kind, attack ideas and not people. Disagreement is how a spec like this gets better; bad faith is not.
