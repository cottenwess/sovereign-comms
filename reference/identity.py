"""
GhostBox Protocol - Spirit Layer reference (Python)
Identity derivation: Quad-Key -> Locator Hash (public) + Access Token seed (private)

ILLUSTRATIVE reference. The canonical implementation is TypeScript (../src/identity.ts),
because derivation must run client-side on the user's device (SPEC Principle 1).
This file exists so readers of the book *Notes from an Acceleration Native* can
cross-check the corrected construction in the language the book uses, and so both
languages can be validated against the same test vectors.

This file is corrected to FULL PARITY with src/identity.ts (deliberate):
  - Salts and key seeds use real RFC 5869 HKDF (Extract + Expand), byte-for-byte
    identical to @noble/hashes `hkdf`. The earlier bare-HMAC formulation was a
    bug: it did NOT match the canonical TypeScript and produced a different
    identity per language. See SPEC §3.3.
  - Entropy is MEASURED with zxcvbn for "know" factors (caller no longer supplies
    the number), with per-class caps and a diversity rule. See SPEC §3.2.
  - Variable factor composite; keypairs derived from the Access Token seed.
  - The composite and salts are held in bytearrays and zeroed in a finally block.
    Best-effort only: any `know` factor that existed as a Python `str`/`bytes`
    before reaching this layer cannot be wiped (immutable). See SECURITY.md.

Dependencies:
    pip install argon2-cffi cryptography zxcvbn

License: AGPL-3.0-or-later
Copyright (C) 2026 Cory A. Ottenwess
"""

from __future__ import annotations

import hashlib
import hmac
import math
import unicodedata
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from zxcvbn import zxcvbn

UNIT_SEP = b"\x1f"  # factor separator; cannot appear in NFC text or hashes
MIN_ENTROPY_BITS = 128

# Versioned parameter ladder (SPEC §3.4). memory_kib in KiB.
ARGON_PARAMS = {
    "argon2id-v1": dict(memory_kib=65536, iterations=4, parallelism=4),   # 64 MiB
    "argon2id-v2": dict(memory_kib=262144, iterations=4, parallelism=4),  # 256 MiB
}

# Per-class entropy caps (SPEC §3.2), identical to src/identity.ts.
CLASS_CAP_BITS = {"know": 80, "are": 24, "have": 64, "who": 64}


@dataclass(frozen=True)
class Factor:
    """A single Quad-Key factor.

    cls: one of "know" | "are" | "have" | "who"
    data: bytes for this factor (NFC UTF-8 for "know"; a fixed-length HASH
          otherwise, never the raw data).
    entropy_bits: MEASURED for "know", declared-and-capped otherwise. Set by the
                  constructors below, NOT by the caller.
    """
    cls: str
    data: bytes
    entropy_bits: float


def text_factor(secret: str) -> Factor:
    """Build a 'know' factor from text. Entropy is MEASURED with zxcvbn here, so
    the layer does not trust a caller-supplied number (SPEC §3.2).

    NOTE: zxcvbn is a heuristic and English-biased. It raises the floor; it does
    not make the floor honest.
    """
    normalized = unicodedata.normalize("NFC", secret)
    guesses = max(zxcvbn(normalized)["guesses"], 2)
    bits = min(math.log2(guesses), CLASS_CAP_BITS["know"])
    return Factor("know", normalized.encode("utf-8"), bits)


def hashed_factor(cls: str, digest: bytes, declared_bits: float,
                  provenance: str) -> Factor:
    """Build an 'are'/'have'/'who' factor from a fixed-length HASH of the
    underlying material (never the raw biometric / document / contact data).

    declared_bits: caller's estimate for the SOURCE; capped by class.
    provenance:    required audit tag; not used in derivation.
    """
    if cls not in ("are", "have", "who"):
        raise ValueError("hashed_factor class must be 'are' | 'have' | 'who'.")
    if not provenance:
        raise ValueError("hashed_factor requires a provenance tag (SPEC §3.2).")
    return Factor(cls, digest, min(declared_bits, CLASS_CAP_BITS[cls]))


def canonicalize(factors: list[Factor]) -> bytearray:
    """Composite per SPEC §3.6. Order is user-fixed and part of the secret.
    Returns a mutable bytearray so it can be zeroed after use."""
    if len(factors) < 4:
        raise ValueError("Quad-Key requires at least 4 factors (SPEC §3.2).")
    out = bytearray()
    for i, f in enumerate(factors):
        out += f.data
        if i < len(factors) - 1:
            out += UNIT_SEP
    return out


def assert_entropy_floor(factors: list[Factor]) -> None:
    """Enforce the entropy floor AND factor diversity (SPEC §3.2). The sum must
    clear MIN_ENTROPY_BITS and no single factor may supply more than half of it."""
    bits = sum(f.entropy_bits for f in factors)
    if bits < MIN_ENTROPY_BITS:
        raise ValueError(
            f"Composite entropy {bits:.1f} bits < required {MIN_ENTROPY_BITS} (SPEC §3.2)."
        )
    if max(f.entropy_bits for f in factors) > bits / 2:
        raise ValueError(
            "No single factor may supply more than half the entropy floor (SPEC §3.2)."
        )


def _hkdf(ikm: bytes, info: bytes, length: int = 32,
          salt: bytes | None = None) -> bytes:
    """RFC 5869 HKDF-SHA256 (Extract + Expand). Byte-for-byte identical to
    @noble/hashes `hkdf(sha256, ikm, salt, info, length)`. When salt is None,
    RFC 5869 / noble use HashLen (32) zero bytes (SPEC §3.3)."""
    if salt is None:
        salt = b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()           # Extract
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()  # Expand
        okm += t
        counter += 1
    return bytes(okm[:length])


def _hkdf_salt(composite: bytes, label: bytes) -> bytes:
    """Per-composite salt via full HKDF (SPEC §3.3). Matches src/identity.ts
    `hkdfSalt`: hkdf(sha256, composite, salt=undefined, info=label, L=32)."""
    return _hkdf(composite, label, 32)


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
    or transmit access_seed or the private keys. The composite and salts owned by
    this function are zeroed on every exit path.
    """
    assert_entropy_floor(factors)
    params = ARGON_PARAMS[param_version]
    composite = canonicalize(factors)
    salt_locator = bytearray()
    salt_access = bytearray()
    try:
        salt_locator += _hkdf_salt(composite, b"ghostbox/v1/locator")
        salt_access += _hkdf_salt(composite, b"ghostbox/v1/access")

        locator_hash = _argon(composite, bytes(salt_locator), 16, params)
        access_seed = _argon(composite, bytes(salt_access), 32, params)

        # Keypairs from the access seed via domain-separated HKDF so the two
        # keypairs are independent and neither equals the raw seed.
        sign_seed = _hkdf(access_seed, b"ghostbox/v1/sign", 32)
        enc_seed = _hkdf(access_seed, b"ghostbox/v1/enc", 32)

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
        for buf in (composite, salt_locator, salt_access):
            for i in range(len(buf)):
                buf[i] = 0


if __name__ == "__main__":
    import hashlib as _h

    # The book's passphrase-only Quad-Key is the WEAKEST config and, under
    # measured entropy, is REFUSED (matches src/identity.ts and SPEC §3.2).
    weak = [text_factor(w) for w in ("Nebula", "77", "Correct", "Horse")]
    try:
        derive_identity(weak)
        print("UNEXPECTED: weak passphrase-only key was accepted")
    except ValueError as e:
        print("Weak passphrase-only key correctly refused:", e)

    # A strong mixed-factor Quad-Key (one know + three hashed factors).
    strong = [
        text_factor("correct horse battery staple plenitude"),
        hashed_factor("have", _h.sha256(b"yubikey-secret").digest(), 64, "yubikey-hmac"),
        hashed_factor("who", _h.sha256(b"recovery-contact").digest(), 64, "ssi-vc"),
        hashed_factor("are", _h.sha256(b"fingerprint-template").digest(), 24, "fido2-prf"),
    ]
    ident = derive_identity(strong)
    print("Locator Hash (public):", ident.locator_hash.hex())
    print("Signing pubkey:       ", ident.signing_public.hex())
    print("Encryption pubkey:    ", ident.encryption_public.hex())
    print("Access seed is PRIVATE and intentionally not printed in full.")
