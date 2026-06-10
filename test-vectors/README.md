# Test Vectors

Frozen cross-language vectors for the Spirit Layer (identity derivation).

**`identity.json`** — the canonical vectors. Both implementations
(`src/identity.ts` canonical, `reference/identity.py`) MUST reproduce every
`expected` value byte-for-byte. They are regenerated from the real modules and
were verified identical across languages on generation.

**The checkers import the real modules. They do not reimplement.** This is
deliberate: an earlier checker reimplemented derivation inline, which let the
two languages silently diverge (the module used full HKDF while the inline copy
used bare HMAC) while CI stayed green. Checkers now call the actual
`deriveIdentity` / `text_factor` / `hashed_factor` exports.

- `verify_vectors.mts` — TypeScript checker (run with `npx tsx`); imports `../src/identity.ts`.
- `verify_vectors.py` — Python checker; imports `../reference/identity.py`.

Vectors cover: a strong mixed-factor identity (the positive case), an
ordering-sensitivity check (same factors reordered MUST differ, since order is
part of the secret), the book's passphrase-only key now correctly REFUSED for
falling below the measured 128-bit floor, and a diversity-rule violation that
MUST be refused.

Hashed-factor inputs are given as `sha256_of` preimages so both languages
reproduce the digest. Regenerate vectors only via a reviewed parity run.

## Other runnable checks (not frozen vectors)

- `integration.mts` — Spirit + Specter end to end (real modules).
- `atproto-bridge.mts` — AT Proto discovery → private message (real modules, network mocked).
- `verify_unlinkability.mjs` — demonstrates the server holds no social graph.
