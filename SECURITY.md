# Security Policy

## Reporting a vulnerability

**Do not open a public issue or pull request for a security vulnerability.**

This project is privacy and communication infrastructure. A publicly disclosed
flaw can expose real users before a fix exists. Report privately.

**How:** use GitHub's private vulnerability reporting. Go to the
[**Security tab**](../../security) of this repository and click
**Report a vulnerability**. This opens a private report visible only to the
maintainers, not a public issue. Please include:

- a description of the vulnerability,
- the spec section or file affected,
- a proof-of-concept if you have one,
- the impact as you understand it.

The report and any follow-up discussion stay private on GitHub until a fix is
ready and an advisory is published. Please allow a reasonable window for a fix
before public disclosure. You will be credited in the published advisory unless
you prefer to remain anonymous.

## Scope

In scope: the specification's security claims and the reference implementations.
The properties the protocol claims to provide, and where to find them:

| Property | Spec section | Implementation |
|---|---|---|
| Application-layer sender/recipient unlinkability | §4 | `src/transport.ts` |
| Identity derivation (Spirit Layer) | §3 | `src/identity.ts` |
| Duress identity | §3.7 | `src/identity.ts` |
| Forward secrecy (in-channel, v0.4.0) | §6.2 | `src/ratchet.ts`, `src/transport.ts` |
| Key commitment (UtC envelope) | §6.3 | `src/envelope.ts` |
| Ratchet-state sync | §6.4 | `src/statesync.ts` |
| Sender anonymity (pre-session Lobby path) | §5.7 | `src/transport.ts` |

Known and documented limitations are **not** vulnerabilities. See
[SPECIFICATION.md](./SPECIFICATION.md) for the full threat model and the
honestly-named non-properties: no post-compromise security, no network-layer
anonymity, no audit. Network-layer correlation, endpoint compromise, and
user-chosen weak factors are explicitly out of the protocol's cryptographic
scope and must be handled by the deployment.

## Requesting a review

If you are a cryptographer interested in reviewing the constructions rather
than reporting a specific vulnerability, [CRYPTO_REVIEW.md](./CRYPTO_REVIEW.md)
is the right starting point. It describes the threat model, the exact
constructions, the properties claimed and not claimed, and the five places most
likely to be wrong. Feedback there is welcome as an issue or a pull request.

## A note on the reference code

The reference implementations are readable demonstrations of correct
construction, not hardened libraries. They have not been independently audited.
Do not deploy them as-is. An independent audit is a prerequisite this project
has not yet met, and that fact is stated plainly rather than glossed.

The v0.4.0 forward-secrecy wiring (the `RatchetSession` path in
`src/transport.ts`, the ratchet-state serialization in `src/statesync.ts`, and
their integration test in `test-vectors/fs-transport.mts`) was built with
AI assistance (Claude, Anthropic) and has not been reviewed by an independent
cryptographer. It is the primary target of the review request in
[CRYPTO_REVIEW.md](./CRYPTO_REVIEW.md).
