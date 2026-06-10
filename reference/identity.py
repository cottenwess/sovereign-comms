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

Dependencies:
    pip install argon2-cffi cryptography

License: AGPL-3.0-or-later
Copyright (C) 2026 Cory A. Ottenwess
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

UNIT_SEP = b"\x1f"  # factor separator; cannot appear in NFC text or hashes
MIN_ENTROPY_BITS = 128

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
    entropy_bits: estimated contribution (caller supplies; see SPEC §3.2)
    """
    cls: str
    data: bytes
    entropy_bits: int


def text_factor(secret: str, entropy_bits: int) -> Factor:
    """Build a 'know' factor from text (NFC-normalized)."""
    return Factor("know", unicodedata.normalize("NFC", secret).encode("utf-8"),
                  entropy_bits)


def canonicalize(factors: list[Factor]) -> bytes:
    """Composite per SPEC §3.6. Order is user-fixed and part of the secret."""
    if len(factors) < 4:
        raise ValueError("Quad-Key requires at least 4 factors (SPEC §3.2).")
    return UNIT_SEP.join(f.data for f in factors)


def assert_entropy_floor(factors: list[Factor]) -> None:
    bits = sum(f.entropy_bits for f in factors)
    if bits < MIN_ENTROPY_BITS:
        raise ValueError(
            f"Composite entropy {bits} bits < required {MIN_ENTROPY_BITS} (SPEC §3.2)."
        )


def _hkdf_salt(composite: bytes, label: bytes) -> bytes:
    """HKDF-Extract (SHA-256): 32-byte per-composite salt (SPEC §3.3)."""
    return hmac.new(label, composite, hashlib.sha256).digest()


def _hkdf_expand(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Minimal HKDF-Expand (SHA-256), single block (length<=32)."""
    return hmac.new(ikm, info + b"\x01", hashlib.sha256).digest()[:length]


def _argon(composite: bytes, salt: bytes, length: int, p: dict) -> bytes:
    return hash_secret_raw(
        secret=composite,
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
    or transmit access_seed or the private keys.
    """
    assert_entropy_floor(factors)
    params = ARGON_PARAMS[param_version]
    composite = canonicalize(factors)

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


if __name__ == "__main__":
    # Passphrase-only variant from the book (weakest valid config; for demo only).
    # Entropy values here are illustrative placeholders, not a real estimate.
    demo = [
        text_factor("Nebula", 40),
        text_factor("77", 24),
        text_factor("Correct", 40),
        text_factor("Horse", 40),
    ]
    ident = derive_identity(demo)
    print("Locator Hash (public):", ident.locator_hash.hex())
    print("Signing pubkey:       ", ident.signing_public.hex())
    print("Encryption pubkey:    ", ident.encryption_public.hex())
    print("Access seed is PRIVATE and intentionally not printed in full.")
