#!/usr/bin/env python3
"""
Test-vector checker for the Python reference implementation.

Loads test-vectors/identity.json and asserts that reference/identity.py
reproduces every frozen 'expected' value exactly. Also enforces the
order-sensitivity invariant (must_differ_from) and the entropy-floor throw.

The frozen vectors were verified cross-language (TypeScript canonical +
Python reference) at generation time. This script is what keeps the Python
side honest in CI; the TS side has its own checker (verify_vectors.mjs).

NOTE on entropy: text_factor() now measures entropy internally via zxcvbn.
The optional 'entropy_bits' field in the JSON factor spec is documentation
only and is NOT passed to text_factor — the layer ignores caller-supplied
numbers for 'know' factors. The 'below-entropy-floor' vector uses genuinely
weak single-character factors that zxcvbn scores near zero; the throw is
produced by real measurement, not a fabricated low number.

Exit code 0 = all pass. Non-zero = a mismatch, which means either the
implementation drifted or the vectors were changed without regeneration.

Run from the repository root:
    python test-vectors/verify_vectors.py

License: AGPL-3.0-or-later
Copyright (C) 2026 Cory A. Ottenwess
"""

import json
import sys
from pathlib import Path

# Make the reference module importable regardless of CWD.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "reference"))

from identity import derive_identity, text_factor  # noqa: E402

VECTORS = ROOT / "test-vectors" / "identity.json"


def build_factors(spec):
    """Turn a vector's factor list into Factor objects.

    Only 'know' factors are handled here. Add hashed_factor support when
    non-know vectors are introduced. Entropy is measured by text_factor
    internally; the optional 'entropy_bits' field in the JSON is ignored.
    """
    factors = []
    for f in spec["factors"]:
        if f["class"] != "know":
            raise SystemExit(
                f"checker only handles 'know' factors; got {f['class']}. "
                "Add hashed_factor handling here when non-know vectors are introduced."
            )
        factors.append(text_factor(f["text"]))
    return factors


def main() -> int:
    data = json.loads(VECTORS.read_text())
    results = {}
    failures = []

    for vec in data["vectors"]:
        name = vec["name"]
        pv = vec.get("param_version", "argon2id-v1")
        expected = vec["expected"]

        # Throw case.
        if expected.get("throws"):
            try:
                derive_identity(build_factors(vec), pv)
            except Exception as e:  # noqa: BLE001
                needle = expected.get("error_contains", "")
                if needle and needle.lower() not in str(e).lower():
                    failures.append(
                        f"{name}: threw, but message missing '{needle}': {e}"
                    )
                else:
                    print(f"PASS  {name} (correctly raised)")
            else:
                failures.append(f"{name}: expected a throw, none occurred")
            continue

        # Derivation case.
        ident = derive_identity(build_factors(vec), pv)
        got = {
            "locator_hash_hex": ident.locator_hash.hex(),
            "signing_public_hex": ident.signing_public.hex(),
            "encryption_public_hex": ident.encryption_public.hex(),
        }
        results[name] = got

        mismatched = [
            k for k in ("locator_hash_hex", "signing_public_hex", "encryption_public_hex")
            if k in expected and got[k] != expected[k]
        ]
        if mismatched:
            for k in mismatched:
                failures.append(
                    f"{name}.{k}: expected {expected[k]} got {got[k]}"
                )
        else:
            print(f"PASS  {name}")

    # Order-sensitivity / distinctness invariants.
    for vec in data["vectors"]:
        other = vec.get("must_differ_from")
        if other and vec["name"] in results and other in results:
            if results[vec["name"]] == results[other]:
                failures.append(
                    f"{vec['name']} MUST differ from {other} but produced identical identity"
                )
            else:
                print(f"PASS  {vec['name']} differs from {other}")

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print("  -", f)
        return 1

    print("\nAll vectors passed (Python reference).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
