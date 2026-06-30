"""
Cross-language vector checker (Python) - imports the REAL module.

Like its TypeScript sibling, this does NOT reimplement derivation. It calls the
actual reference/identity.py exports, so any divergence between the module and
the frozen vectors is caught here. Checkers import; they do not reimplement.

Run from repo root:  python test-vectors/verify_vectors.py

License: AGPL-3.0-or-later
Copyright (C) 2026 Cory A. Ottenwess
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reference"))
from identity import derive_identity, text_factor, hashed_factor  # noqa: E402

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "identity.json"), encoding="utf-8") as fh:
    DATA = json.load(fh)


def build_factor(vf):
    if vf["class"] == "know":
        return text_factor(vf["text"])
    digest = hashlib.sha256(vf["sha256_of"].encode("utf-8")).digest()
    return hashed_factor(vf["class"], digest, vf.get("declared_bits", 0),
                         vf.get("provenance", ""))


seen = {}
passed = 0
failures = []


def ok(name, cond):
    global passed
    if cond:
        print(f"PASS  {name}")
        passed += 1
    else:
        print(f"FAIL  {name}", file=sys.stderr)
        failures.append(name)


for v in DATA["vectors"]:
    factors = [build_factor(f) for f in v["factors"]]
    exp = v["expected"]
    if exp.get("throws"):
        threw = False
        msg = ""
        try:
            derive_identity(factors, v["param_version"])
        except Exception as e:  # noqa: BLE001
            threw = True
            msg = str(e).lower()
        ok(f"{v['name']} (must throw)",
           threw and exp.get("error_contains", "").lower() in msg)
        continue
    ident = derive_identity(factors, v["param_version"])
    loc = ident.locator_hash.hex()
    ok(f"{v['name']} locator", loc == exp["locator_hash_hex"])
    ok(f"{v['name']} signing", ident.signing_public.hex() == exp["signing_public_hex"])
    ok(f"{v['name']} encryption",
       ident.encryption_public.hex() == exp["encryption_public_hex"])
    if "must_differ_from" in v:
        other = seen.get(v["must_differ_from"])
        ok(f"{v['name']} differs from {v['must_differ_from']}",
           other is not None and other != loc)
    seen[v["name"]] = loc

if failures:
    print(f"\n{len(failures)} FAILURE(S): {', '.join(failures)}", file=sys.stderr)
    sys.exit(1)
print(f"\nAll {passed} checks passed (Python reference, real module imported).")
