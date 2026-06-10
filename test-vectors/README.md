# Test Vectors

Cross-language conformance vectors. The TypeScript canonical implementation
(`../src`) and the Python reference (`../reference`) both reproduce every vector
here byte-for-byte. These values were generated and verified across both
languages at the same time — if the two ever diverge, one implementation has
drifted, and that is exactly what these vectors exist to catch.

## Status

**Frozen and enforced.** `identity.json` holds verified expected values. Two
checkers validate against them, and both run in CI on every push and PR:

- `verify_vectors.mjs` — checks the TypeScript canonical implementation
- `verify_vectors.py` — checks the Python reference implementation

Run locally from the repository root:

```bash
node test-vectors/verify_vectors.mjs    # or: npm test
python test-vectors/verify_vectors.py   # or: npm run test:py
```

> Changing any value in `identity.json` without regenerating from a reviewed run
> will break the checkers — by design. The frozen values pin the derivation;
> they are not meant to be edited by hand.

## What the vectors cover

- **`passphrase-only-book-demo`** — the four-word key from the book's Appendix B.
  Weakest valid configuration; included to pin the documented example, not as a
  recommended key composition.
- **`ordering-sensitivity`** — the same four factors reordered. Produces a
  completely different identity, proving factor order is part of the secret
  (SPEC §3.6). The checkers assert it differs from the demo above.
- **`below-entropy-floor`** — a composite under the 128-bit floor. Derivation
  MUST throw (SPEC §3.2); the checkers assert the throw.

## Format (`identity.json`)

```jsonc
{
  "name": "passphrase-only-book-demo",
  "param_version": "argon2id-v1",
  "factors": [
    { "class": "know", "text": "Nebula" }
    // ...
  ],
  "expected": {
    "locator_hash_hex": "...",
    "signing_public_hex": "...",
    "encryption_public_hex": "..."
  }
}
```

Notes:
- `factors[].text` is only valid for `class: "know"`. For `are` / `have` / `who`
  factors a vector MUST supply `hash_hex` (the fixed-length factor hash), never
  raw data — the spec forbids raw biometric/document/contact data entering the
  system (SPEC §3.2). The current checkers handle `know` factors only and will
  fail loudly if a non-`know` vector is added before that support is written.
- Private outputs (access seed, private keys) are intentionally NOT stored.
  Vectors pin public outputs only.
- `must_differ_from` asserts two vectors produce distinct identities.
- `expected.throws` + `error_contains` assert a derivation rejects bad input.

## Regenerating (only with review)

If a deliberate, reviewed change to the derivation requires new values:

1. Make the change in BOTH `../src/identity.ts` and `../reference/identity.py`.
2. Run both checkers; they will fail against the old frozen values.
3. Produce the new values from a clean run of both languages and confirm they
   agree with each other before writing them into `identity.json`.
4. Only then commit the updated vectors, with the reasoning in the commit.

## Coverage still wanted

Contributions welcome (see `../CONTRIBUTING.md`):

- A mixed-factor composite (know + have + are) using `hash_hex` factors, plus the
  checker support to handle non-`know` classes.
- A vector under `argon2id-v2` params to pin the second ladder rung.
- Additional canonicalization edge cases (NFC normalization boundaries, the
  unit-separator boundary).
