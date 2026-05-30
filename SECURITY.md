# Security Policy

## Reporting a vulnerability

**Do not open a public issue or pull request for a security vulnerability.**

This project is privacy and communication infrastructure. A publicly disclosed
flaw can expose real users before a fix exists. Report privately.

**How:** use GitHub's private vulnerability reporting. Go to the
[**Security tab**](../../security) of this repository and click
**Report a vulnerability**. This opens a private report visible only to the
maintainers — not a public issue. Please include:

- a description of the vulnerability,
- the spec section or file affected,
- a proof-of-concept if you have one,
- the impact as you understand it.

The report and any follow-up discussion stay private on GitHub until a fix is
ready and an advisory is published. Please allow a reasonable window for a fix
before public disclosure. You will be credited in the published advisory unless
you prefer to remain anonymous.

## Scope

In scope: the specification's security claims (especially unlinkability §4,
identity derivation §3, duress mode §3.7, forward secrecy §6.2), and the
reference implementations.

Known and documented limitations are **not** vulnerabilities — see
[SPECIFICATION.md §8.3 and §8.4](./SPECIFICATION.md#8-threat-model). Network-layer
correlation, endpoint compromise, and user-chosen weak factors are explicitly
out of the protocol's cryptographic scope and must be handled by the deployment.

## A note on the reference code

The reference implementations are readable demonstrations of correct
construction, not hardened libraries. They have not been independently audited.
Do not deploy them as-is. An independent audit is a prerequisite this project
has not yet met, and that fact is stated plainly rather than glossed.

## Known limitations of the reference implementations

These are documented constraints, not vulnerabilities. They are stated here so a
consuming client handles them rather than assuming the Spirit Layer does.

### Secret erasure is best-effort, not guaranteed

The reference code zeros the composite (and, in TypeScript, the per-composite
salts) in a `finally` block on every exit path. That is the most a managed
runtime can offer, and it is not erasure.

- Any **"know"** factor that existed as a `string` (TypeScript) or `str`
  (Python) before it reached the layer **cannot be wiped by anyone**, because
  strings are immutable and live in the heap until garbage collection chooses to
  reclaim them. The same applies to Python `bytes`; only `bytearray` and
  `Uint8Array` can be zeroed in place.
- JavaScript engines (V8) and the Python runtime copy and intern buffers during
  normal operation, so traces of unhashed factors may survive in RAM longer than
  the explicit wipe suggests.

Mitigation: keep the secret's lifetime as short as possible and, for
high-security callers, accept pre-encoded bytes at the API boundary so the layer
never holds the immutable string. A deployment that requires a genuine erasure
guarantee should use a native-language client with explicit memory management.
The reference code's `fill(0)` is harm reduction, not a guarantee.

### Entropy estimation raises the floor; it does not make it honest

The 128-bit entropy floor (SPEC §3.2) is enforced with a measured estimate, not
a caller-supplied number: `"know"` factors are scored with
[zxcvbn](https://github.com/zxcvbn-ts/zxcvbn), and other factor classes declare
an entropy value that is capped by class. Two honest caveats:

- **zxcvbn is a heuristic and English-biased.** A structured-but-guessable
  passphrase, or one built from non-English patterns the dictionaries don't
  cover, will be over-rated. The gate is a meaningful floor, not a proof of
  unguessability.
- **A biometric is not a secret.** The `"are"` factor class is capped low and
  must never be load-bearing: biometric material is low-entropy and, unlike a
  passphrase, cannot be revoked or rotated after compromise.

A client should still run its own estimator at onboarding and refuse weak
configurations before they ever reach derivation.
