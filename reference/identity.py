"""
GhostBox Protocol - Spirit Layer reference (Python)
Identity derivation: Quad-Key -> Locator Hash (public) + Access Token seed (private)

ILLUSTRATIVE reference. The canonical implementation is TypeScript (../src/identity.ts),
because derivation must run client-side on the user's device (SPEC Principle 1).
This file exists so readers of the book *Notes from an Acceleration Native* can
cross-check the corrected construction in the language the book uses, and so both
languages can be validated against the same test vectors.

Corrections vs. the book's Appendix B snippet (deliberate - see SPEC §0.4):
  - Per-composite salts via HKDF (not static salts)
  - Variable factor composite (not a fixed 4 words)
  - Keypairs derived from the Access Token seed

Corrections vs. the prior revision of THIS file (deliberate):
  - HKDF is now real RFC 5869 (Extract + Expand) so it matches the canonical
    TypeScript byte-for-byte. The previous _hkdf_salt was a single HMAC and
    _hkdf_expand skipped the Extract step; the two languages did not agree and
    no shared test vector could pass. They agree now.
  - The entropy floor is measured, not asserted. "know" factors are scored with
    zxcvbn inside this layer; the caller no longer supplies the number. Other
    classes carry a declared estimate capped by class (a biometric hash is not a
    password and must not be load-bearing).
  - The composite is a bytearray and is zeroed in a finally block. This is
    best-effort; see SECURITY.md for what a managed runtime cannot guarantee.

Dependencies:
    pip install argon2-cffi cryptography zxcvbn

License: AGPL-3.0-or-later
Copyright (C) 2026 Cory A. Ottenwess
"""

from __future__ import annotations

import math
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from zxcvbn import zxcvbn

UNIT_SEP = b"\x1f"  # factor separator; cannot appear in NFC text or hashes
MIN_ENTROPY_BITS = 128

# Per-class entropy caps (SPEC §3.2). A "know" factor is measured by zxcvbn and
# capped so a single long passphrase can't claim the whole floor. "are"
# (biometric) is capped HARD and low: biometrics are low-entropy and, more
# importantly, NON-REVOCABLE, so they must never be load-bearing. "have"
# (hardware token) and "who" (SSI credential / contact) can carry real declared
# entropy with provenance, still capped to force genuine factor diversity.
CLASS_CAP_BITS = {"know": 80, "are": 24, "have": 64, "who": 64}

# Versioned parameter ladder (SPEC §3.4). memory_kib in KiB to match the book.
ARGON_PARAMS = {
    "argon2id-v1": dict(memory_kib=65536, iterations=4, parallelism=4),   # 64 MiB
    "argon2id-v2": dict(memory_kib=262144, iterations=4, parallelism=4),  # 256 MiB
}


@dataclass(frozen=True)
class Factor:
    """A single Quad-Key factor.

    cls: one of "know" | "are" | "have" | "who"
    data: bytes for this factor.
        - "know": NFC-normalized UTF-8 of the secret text
        - others: the fixed-length HASH of the factor, never the raw data
    entropy_bits: estimated contribution. Set by the constructors below, NOT by
        an arbitrary caller value (SPEC §3.2). For "know" it is measured here;
        for other classes it is a declared value capped by class.
    """
    cls: str
    data: bytes
    entropy_bits: float


def text_factor(secret: str) -> Factor:
    """Build a 'know' factor from text. Entropy is MEASURED with zxcvbn here, so
    the layer no longer trusts a caller-supplied number.

    NOTE: zxcvbn is a heuristic and English-biased. It raises the floor; it does
    not make the floor honest. A structured-but-guessable passphrase will still
    flatter itself. See SPEC §3.2.
    """
    normalized = unicodedata.normalize("NFC", secret)
    guesses = max(zxcvbn(normalized)["guesses"], 2)
    bits = min(math.log2(guesses), CLASS_CAP_BITS["know"])
    return Factor("know", normalized.encode("utf-8"), bits)


def hashed_factor(cls: str, digest: bytes, declared_bits: float, provenance: str) -> Factor:
    """Build an 'are' / 'have' / 'who' factor from a fixed-length HASH of the
    underlying material (never the raw biometric/document/contact data).

    declared_bits is the caller's entropy estimate for the SOURCE; it is capped
    by class. provenance is a free-text tag for auditability (e.g. "yubikey-hmac",
    "fido2-prf", "ssi-vc") and is not used in derivation.
    """
    if cls not in ("are", "have", "who"):
        raise ValueError(f"hashed_factor class must be are|have|who, got {cls!r}")
    if not provenance:
        raise ValueError("hashed_factor requires a provenance tag (SPEC §3.2).")
    return Factor(cls, bytes(digest), min(float(declared_bits), CLASS_CAP_BITS[cls]))


def canonicalize(factors: list[Factor]) -> bytearray:
    """Composite per SPEC §3.6. Order is user-fixed and part of the secret.

    Returns a bytearray (not bytes) so derive_identity can zero it afterward;
    bytes is immutable and cannot be wiped at all.
    """
    if len(factors) < 4:
        raise ValueError("Quad-Key requires at least 4 factors (SPEC §3.2).")
    return bytearray(UNIT_SEP.join(f.data for f in factors))


def assert_entropy_floor(factors: list[Factor]) -> None:
    """Enforce the floor AND factor diversity. The sum must clear MIN_ENTROPY_BITS
    and no single factor may supply more than half of it, which is the other way
    a naive caller defeats a '128-bit' gate (SPEC §3.2)."""
    bits = sum(f.entropy_bits for f in factors)
    if bits < MIN_ENTROPY_BITS:
        raise ValueError(
            f"Composite entropy {bits:.1f} bits < required {MIN_ENTROPY_BITS} (SPEC §3.2)."
        )
    if max(f.entropy_bits for f in factors) > bits / 2:
        raise ValueError(
            "No single factor may supply more than half the entropy floor (SPEC §3.2)."
        )


def _hkdf_salt(composite: bytes, label: bytes) -> bytes:
    """HKDF (SHA-256), salt=None per RFC 5869, info=label -> 32-byte per-composite
    salt (SPEC §3.3). Matches hkdf(sha256, composite, undefined, label, 32) in the
    canonical TypeScript byte-for-byte."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label).derive(bytes(composite))


def _hkdf_expand(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Full RFC 5869 HKDF (Extract THEN Expand). The previous version used the
    access seed directly as the PRK and skipped Extract, which broke parity."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(bytes(ikm))


def _argon(composite: bytes, salt: bytes, length: int, p: dict) -> bytes:
    return hash_secret_raw(
        secret=bytes(composite),
        salt=salt,
        time_cost=p["iterations"],
        memory_cost=p["memory_kib"],
        parallelism=p["parallelism"],
        hash_len=length,
        type=Type.ID,  # Argon2id
    )


@dataclass(frozen=True)
class Identity:
    locator_hash: bytes        # PUBLIC, 16 bytes
    access_seed: bytes         # PRIVATE, 32 bytes - RAM only
    signing_private: bytes     # PRIVATE - Ed25519 raw seed
    signing_public: bytes      # PUBLIC
    encryption_private: bytes  # PRIVATE - X25519 raw
    encryption_public: bytes   # PUBLIC
    param_version: str


def derive_identity(factors: list[Factor],
                    param_version: str = "argon2id-v1") -> Identity:
    """Derive a full GhostBox identity from a composite Quad-Key.

    SECURITY: private material lives only as long as you keep it. Do not persist
    or transmit access_seed or the private keys. The composite is zeroed here on
    every exit path; the returned private material is the caller's to zero.
    """
    assert_entropy_floor(factors)
    params = ARGON_PARAMS[param_version]
    composite = canonicalize(factors)
    try:
        salt_locator = _hkdf_salt(composite, b"ghostbox/v1/locator")
        salt_access = _hkdf_salt(composite, b"ghostbox/v1/access")

        locator_hash = _argon(composite, salt_locator, 16, params)
        access_seed = _argon(composite, salt_access, 32, params)

        sign_seed = _hkdf_expand(access_seed, b"ghostbox/v1/sign")
        enc_seed = _hkdf_expand(access_seed, b"ghostbox/v1/enc")

        sign_priv = Ed25519PrivateKey.from_private_bytes(sign_seed)
        enc_priv = X25519PrivateKey.from_private_bytes(enc_seed)

        raw = serialization.Encoding.Raw
        pub_fmt = serialization.PublicFormat.Raw
        signing_public = sign_priv.public_key().public_bytes(raw, pub_fmt)
        encryption_public = enc_priv.public_key().public_bytes(raw, pub_fmt)

        return Identity(
            locator_hash=locator_hash,
            access_seed=access_seed,
            signing_private=sign_seed,
            signing_public=signing_public,
            encryption_private=enc_seed,
            encryption_public=encryption_public,
            param_version=param_version,
        )
    finally:
        # best-effort wipe of the composite (the one secret this layer owns).
        for i in range(len(composite)):
            composite[i] = 0


if __name__ == "__main__":
    # A realistic mix that actually clears the floor: a strong passphrase plus a
    # hardware token plus an SSI credential plus a biometric (capped, not
    # load-bearing). The book's old "Correct Horse" demo is intentionally gone:
    # under measured entropy it FAILS the floor, which is the point.
    import os, hashlib

    def h(b: bytes) -> bytes:
        return hashlib.sha256(b).digest()

    factors = [
        text_factor("tangerine-sextant-glacier-quibble-77"),
        hashed_factor("have", h(os.urandom(32)), declared_bits=128, provenance="yubikey-hmac"),
        hashed_factor("who", h(b"did:example:abc123"), declared_bits=64, provenance="ssi-vc"),
        hashed_factor("are", h(b"biometric-template"), declared_bits=64, provenance="fido2-prf"),
    ]
    ident = derive_identity(factors)
    print("Locator Hash (public):", ident.locator_hash.hex())
    print("Signing pubkey:       ", ident.signing_public.hex())
    print("Encryption pubkey:    ", ident.encryption_public.hex())
    print("Access seed is PRIVATE and intentionally not printed in full.")
