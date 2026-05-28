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
