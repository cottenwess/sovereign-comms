# Test Vectors

Cross-language conformance vectors. The TypeScript canonical implementation
(`../src`) and the Python reference (`../reference`) MUST both reproduce every
vector here byte-for-byte. If they diverge, one of them is wrong — and that is
exactly what these vectors exist to catch.

## Status

**Stub.** `identity.json` contains the *structure* and a placeholder entry. The
real expected values must be generated once and then frozen, because they pin the
derivation. This is a deliberately open task — see "Generating vectors" below —
so that the first committed values are produced by a clean, reviewed run rather
than copied from chat.

## Format (`identity.json`)

```jsonc
{
  "spec_section": "3",
  "argon_param_version": "argon2id-v1",
  "vectors": [
    {
      "name": "passphrase-only-book-demo",
      "note": "Weakest valid config. Book Appendix B words. Demo only.",
      "factors": [
        { "class": "know", "text": "Nebula"  },
        { "class": "know", "text": "77"      },
        { "class": "know", "text": "Correct" },
        { "class": "know", "text": "Horse"   }
      ],
      "expected": {
        "locator_hash_hex": "TODO_GENERATE",
        "signing_public_hex": "TODO_GENERATE",
        "encryption_public_hex": "TODO_GENERATE"
      }
    }
  ]
}
```

Notes on the format:
- `factors[].text` is only valid for `class: "know"`. For `are` / `have` / `who`
  factors a vector MUST supply `hash_hex` (the fixed-length factor hash), never
  raw data — the spec forbids raw biometric/document/contact data entering the
  system (SPEC §3.2).
- Private outputs (`access_seed`, private keys) are intentionally **not** stored
  as expected values. Vectors pin public outputs only.

## Generating vectors (open task)

The first real values should be produced by running both implementations against
the input set and confirming they agree before committing:

1. Run `../reference/identity.py` against each vector's factors.
2. Run the equivalent through `../src/identity.ts`.
3. Confirm `locator_hash_hex`, `signing_public_hex`, `encryption_public_hex`
   match across both languages.
4. Only then write the agreed values into `identity.json` and remove the
   `TODO_GENERATE` markers.

A small generator/checker script (either language) that automates steps 1–3 is a
welcome first contribution — see `../CONTRIBUTING.md`.

## Coverage wanted

- The book demo above (passphrase-only).
- A mixed-factor composite (know + have + are) using `hash_hex` factors.
- A vector at exactly the entropy floor, and one just below it (which MUST throw).
- A vector under `argon2id-v2` params to pin the second ladder rung.
- Canonicalization edge cases: NFC normalization, factor ordering (reordering the
  same factors MUST produce a different identity), and the unit-separator boundary.
