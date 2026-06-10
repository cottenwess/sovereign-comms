/**
 * Integration test — Spirit Layer (identity) + Specter Layer (transport).
 *
 * Drives the dead-drop with REAL derived identities and asserts the full
 * round-trip works: derive -> deposit -> challenge/sign/claim -> decrypt.
 * Also asserts the negative cases that matter for the security story:
 *   - a wrong signer cannot drain a mailbox
 *   - a third party cannot decrypt a blob addressed to someone else
 *
 * Inlines the transport logic the same way verify_vectors.mjs inlines identity,
 * so CI needs no TypeScript build step. Logic MUST track src/transport.ts.
 *
 * Run from repo root:  node test-vectors/integration.mjs
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { argon2id } from "hash-wasm";
import { x25519, ed25519 } from "@noble/curves/ed25519";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { randomBytes } from "@noble/hashes/utils";

const enc = new TextEncoder();
const dec = new TextDecoder();
const UNIT_SEP = 0x1f;
const PARAMS = { memorySize: 65536, iterations: 4, parallelism: 4 };

let pass = 0;
const failures = [];
function check(name, cond) {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
}

// --- Spirit Layer (identity derivation), inlined ---------------------------
function canon(texts) {
  const parts = texts.map((t) => enc.encode(t.normalize("NFC")));
  const total = parts.reduce((n, p) => n + p.length, 0) + (parts.length - 1);
  const out = new Uint8Array(total); let pos = 0;
  parts.forEach((p, i) => { out.set(p, pos); pos += p.length; if (i < parts.length - 1) out[pos++] = UNIT_SEP; });
  return out;
}
const hkdfSalt = (c, label) => hmac(sha256, enc.encode(label), c);
function expand1(ikm, info) {
  const i = enc.encode(info); const m = new Uint8Array(i.length + 1);
  m.set(i, 0); m[i.length] = 0x01; return hmac(sha256, ikm, m);
}
async function argon(c, salt, len) {
  return argon2id({ password: c, salt, parallelism: PARAMS.parallelism,
    iterations: PARAMS.iterations, memorySize: PARAMS.memorySize, hashLength: len, outputType: "hex" });
}
const hexToBytes = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; };

async function derive(texts) {
  const c = canon(texts);
  const locatorHex = await argon(c, hkdfSalt(c, "ghostbox/v1/locator"), 16);
  const accHex = await argon(c, hkdfSalt(c, "ghostbox/v1/access"), 32);
  const acc = hexToBytes(accHex);
  const signSeed = expand1(acc, "ghostbox/v1/sign");
  const encSeed = expand1(acc, "ghostbox/v1/enc");
  return {
    locatorHex,
    signingPrivate: signSeed,
    signingPublic: ed25519.getPublicKey(signSeed),
    encryptionPrivate: encSeed,
    encryptionPublic: x25519.getPublicKey(encSeed),
  };
}

// --- Specter Layer (sealed box + dead-drop), inlined -----------------------
const boxKey = (shared) => hkdf(sha256, shared, undefined, "ghostbox/v1/sealedbox", 32);
function seal(pub, msg) {
  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, pub);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(boxKey(shared), nonce).encrypt(msg);
  const out = new Uint8Array(32 + 24 + ct.length);
  out.set(ephPub, 0); out.set(nonce, 32); out.set(ct, 56);
  return out;
}
function unseal(priv, blob) {
  const ephPub = blob.subarray(0, 32), nonce = blob.subarray(32, 56), ct = blob.subarray(56);
  const shared = x25519.getSharedSecret(priv, ephPub);
  return xchacha20poly1305(boxKey(shared), nonce).decrypt(ct);
}

class DropServer {
  store = new Map(); verifiers = new Map(); challenges = new Map();
  register(loc, pub) { if (!this.verifiers.has(loc)) this.verifiers.set(loc, pub); }
  deposit(loc, ct) { const l = this.store.get(loc) ?? []; l.push(ct); this.store.set(loc, l); }
  challenge(loc) { const n = randomBytes(32); this.challenges.set(loc, n); return n; }
  claim(loc, sig) {
    const n = this.challenges.get(loc), v = this.verifiers.get(loc);
    if (!n) throw new Error("no challenge"); if (!v) throw new Error("no verifier");
    if (!ed25519.verify(sig, n, v)) throw new Error("bad signature");
    this.challenges.delete(loc); const l = this.store.get(loc) ?? []; this.store.delete(loc); return l;
  }
}
function send(server, target, text) { server.deposit(target.locatorHex, seal(target.encryptionPublic, enc.encode(text))); }
function receive(server, me) {
  server.register(me.locatorHex, me.signingPublic);
  const n = server.challenge(me.locatorHex);
  const blobs = server.claim(me.locatorHex, ed25519.sign(n, me.signingPrivate));
  return blobs.map((b) => dec.decode(unseal(me.encryptionPrivate, b)));
}

async function main() {
  const alice = await derive(["Nebula", "77", "Correct", "Horse"]);
  const bob = await derive(["Quasar", "13", "Battery", "Staple"]);
  const carol = await derive(["Pulsar", "42", "Anchor", "Lantern"]);

  // distinct identities
  check("distinct locators", new Set([alice.locatorHex, bob.locatorHex, carol.locatorHex]).size === 3);

  const server = new DropServer();

  // Alice -> Bob, Carol -> Bob
  send(server, { locatorHex: bob.locatorHex, encryptionPublic: bob.encryptionPublic }, "hello bob, it's alice");
  send(server, { locatorHex: bob.locatorHex, encryptionPublic: bob.encryptionPublic }, "bob, carol here");

  // Bob drains and reads both
  const bobMsgs = receive(server, bob);
  check("bob receives 2 messages", bobMsgs.length === 2);
  check("bob reads alice's message", bobMsgs.includes("hello bob, it's alice"));
  check("bob reads carol's message", bobMsgs.includes("bob, carol here"));

  // Round trip the other way: Bob -> Alice
  send(server, { locatorHex: alice.locatorHex, encryptionPublic: alice.encryptionPublic }, "got them, thanks");
  const aliceMsgs = receive(server, alice);
  check("alice receives reply", aliceMsgs.length === 1 && aliceMsgs[0] === "got them, thanks");

  // NEGATIVE: a wrong signer cannot drain Bob's box
  send(server, { locatorHex: bob.locatorHex, encryptionPublic: bob.encryptionPublic }, "second round");
  server.register(bob.locatorHex, bob.signingPublic);
  const nonce = server.challenge(bob.locatorHex);
  let imposterBlocked = false;
  try { server.claim(bob.locatorHex, ed25519.sign(nonce, carol.signingPrivate)); }
  catch { imposterBlocked = true; }
  check("imposter cannot drain another's mailbox", imposterBlocked);

  // NEGATIVE: a third party cannot decrypt a blob addressed to Bob
  const blobForBob = seal(bob.encryptionPublic, enc.encode("secret for bob"));
  let cannotDecrypt = false;
  try { unseal(carol.encryptionPrivate, blobForBob); }
  catch { cannotDecrypt = true; }
  check("third party cannot decrypt another's blob", cannotDecrypt);

  if (failures.length) {
    console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
    process.exit(1);
  }
  console.log(`\nAll ${pass} integration checks passed (Spirit + Specter end to end).`);
}

main().catch((e) => { console.error(e); process.exit(1); });
