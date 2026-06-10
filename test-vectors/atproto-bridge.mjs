/**
 * AT Proto bridge — offline integration test.
 *
 * Proves the full integration LOGIC end to end with the network MOCKED:
 *
 *   derive identity (Spirit)
 *     -> build a com.ghostbox.identity record
 *     -> "publish" it (mock PDS)
 *     -> resolve it back: DID -> DID doc -> PDS -> record -> SendTarget (bridge)
 *     -> send a private message to the resolved target (Specter dead-drop)
 *     -> recipient drains and decrypts
 *
 * What this verifies: the record format, the did:plc / DID-doc / getRecord
 * parsing, the SendTarget reconstruction, and that a message addressed via a
 * resolved AT Proto identity round-trips through the dead-drop.
 *
 * What it does NOT verify: the LIVE AT Proto network. The sandbox cannot reach
 * plc.directory or a PDS, and a real publish needs your credentials. Run the
 * live path yourself per README "Publishing your GhostBox identity". This test
 * injects a mock fetch so the logic is exercised deterministically.
 *
 * Run from repo root:  node test-vectors/atproto-bridge.mjs
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
const P = { memorySize: 65536, iterations: 4, parallelism: 4 };
const toHex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const hexToBytes = (h) => { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a; };

let pass = 0; const failures = [];
const check = (n, c) => { if (c) { console.log(`PASS  ${n}`); pass++; } else { console.error(`FAIL  ${n}`); failures.push(n); } };

// --- Spirit: derive an identity (inlined) ----------------------------------
function canon(texts) {
  const parts = texts.map((t) => enc.encode(t.normalize("NFC")));
  const total = parts.reduce((n, p) => n + p.length, 0) + (parts.length - 1);
  const out = new Uint8Array(total); let pos = 0;
  parts.forEach((p, i) => { out.set(p, pos); pos += p.length; if (i < parts.length - 1) out[pos++] = UNIT_SEP; });
  return out;
}
const salt = (c, l) => hmac(sha256, enc.encode(l), c);
const expand1 = (ikm, info) => { const i = enc.encode(info); const m = new Uint8Array(i.length + 1); m.set(i, 0); m[i.length] = 1; return hmac(sha256, ikm, m); };
const argon = (c, s, len) => argon2id({ password: c, salt: s, parallelism: P.parallelism, iterations: P.iterations, memorySize: P.memorySize, hashLength: len, outputType: "hex" });
async function derive(texts) {
  const c = canon(texts);
  const locatorHex = await argon(c, salt(c, "ghostbox/v1/locator"), 16);
  const acc = hexToBytes(await argon(c, salt(c, "ghostbox/v1/access"), 32));
  const encSeed = expand1(acc, "ghostbox/v1/enc");
  return { locatorHex, encryptionPublic: x25519.getPublicKey(encSeed), encryptionPrivate: encSeed,
           signingPrivate: expand1(acc, "ghostbox/v1/sign"), signingPublic: ed25519.getPublicKey(expand1(acc, "ghostbox/v1/sign")) };
}

// --- Specter: sealed box + dead-drop (inlined) -----------------------------
const boxKey = (s) => hkdf(sha256, s, undefined, "ghostbox/v1/sealedbox", 32);
function seal(pub, msg) {
  const eph = x25519.utils.randomSecretKey(); const ephPub = x25519.getPublicKey(eph);
  const shared = x25519.getSharedSecret(eph, pub); const nonce = randomBytes(24);
  const ct = xchacha20poly1305(boxKey(shared), nonce).encrypt(msg);
  const out = new Uint8Array(56 + ct.length); out.set(ephPub, 0); out.set(nonce, 32); out.set(ct, 56); return out;
}
function unseal(priv, blob) {
  const shared = x25519.getSharedSecret(priv, blob.subarray(0, 32));
  return xchacha20poly1305(boxKey(shared), blob.subarray(32, 56)).decrypt(blob.subarray(56));
}
class DropServer {
  store = new Map(); verifiers = new Map(); challenges = new Map();
  register(l, p) { if (!this.verifiers.has(l)) this.verifiers.set(l, p); }
  deposit(l, ct) { const a = this.store.get(l) ?? []; a.push(ct); this.store.set(l, a); }
  challenge(l) { const n = randomBytes(32); this.challenges.set(l, n); return n; }
  claim(l, sig) { const n = this.challenges.get(l), v = this.verifiers.get(l); if (!ed25519.verify(sig, n, v)) throw new Error("bad sig"); this.challenges.delete(l); const a = this.store.get(l) ?? []; this.store.delete(l); return a; }
}

// --- Bridge: record + resolution (inlined; tracks src/atproto-bridge.ts) ---
const NSID = "com.ghostbox.identity", RKEY = "self";
const buildRecord = (loc, encHex) => ({ $type: NSID, locatorHash: loc, encryptionPublicKey: encHex, protocolVersion: "ghostbox/0.3", createdAt: new Date().toISOString() });

function extractPds(doc) {
  const s = doc.service?.find((x) => x.type === "AtprotoPersonalDataServer" || x.id === "#atproto_pds");
  if (!s?.serviceEndpoint) throw new Error("no PDS endpoint");
  return s.serviceEndpoint.replace(/\/$/, "");
}
async function resolveDidDoc(did, fetchImpl) {
  const res = await fetchImpl(`https://plc.directory/${did}`);
  if (!res.ok) throw new Error(`PLC ${res.status}`);
  return res.json();
}
async function fetchRecord(pds, did, fetchImpl) {
  const url = `${pds}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(did)}&collection=${NSID}&rkey=${RKEY}`;
  const res = await fetchImpl(url);
  if (!res.ok) throw new Error(`getRecord ${res.status}`);
  const body = await res.json();
  if (!body.value || body.value.$type !== NSID) throw new Error("not a ghostbox record");
  return body.value;
}
async function resolveGhostBox(did, fetchImpl) {
  const doc = await resolveDidDoc(did, fetchImpl);
  const rec = await fetchRecord(extractPds(doc), did, fetchImpl);
  return { locatorHex: rec.locatorHash, encryptionPublic: hexToBytes(rec.encryptionPublicKey) };
}

async function main() {
  // Bob derives a GhostBox identity and "publishes" a record.
  const bob = await derive(["Quasar", "13", "Battery", "Staple"]);
  const bobDid = "did:plc:examplebob1234567890abcd";
  const bobPds = "https://pds.example.com";
  const record = buildRecord(bob.locatorHex, toHex(bob.encryptionPublic));

  check("record has correct $type", record.$type === NSID);
  check("record carries bob's locator", record.locatorHash === bob.locatorHex);

  // Mock the AT Proto network: a PLC DID doc + a getRecord response.
  const network = {
    [`https://plc.directory/${bobDid}`]: {
      id: bobDid,
      alsoKnownAs: ["at://bob.example.com"],
      service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: bobPds }],
    },
    [`${bobPds}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(bobDid)}&collection=${NSID}&rkey=${RKEY}`]: {
      uri: `at://${bobDid}/${NSID}/${RKEY}`,
      value: record,
    },
  };
  const mockFetch = async (url) => {
    if (url in network) return { ok: true, status: 200, json: async () => network[url] };
    return { ok: false, status: 404, json: async () => ({}) };
  };

  // Alice resolves Bob's GhostBox address purely from his DID.
  const target = await resolveGhostBox(bobDid, mockFetch);
  check("resolved locator matches bob", target.locatorHex === bob.locatorHex);
  check("resolved key matches bob", toHex(target.encryptionPublic) === toHex(bob.encryptionPublic));

  // Alice messages Bob privately over the dead-drop, using only what she resolved.
  const server = new DropServer();
  server.deposit(target.locatorHex, seal(target.encryptionPublic, enc.encode("found you via AT Proto, here privately")));

  // Bob drains and decrypts.
  server.register(bob.locatorHex, bob.signingPublic);
  const n = server.challenge(bob.locatorHex);
  const blobs = server.claim(bob.locatorHex, ed25519.sign(n, bob.signingPrivate));
  const msgs = blobs.map((b) => dec.decode(unseal(bob.encryptionPrivate, b)));
  check("bob receives the bridged message", msgs.length === 1 && msgs[0] === "found you via AT Proto, here privately");

  // NEGATIVE: a DID with no published record resolves to a clear failure.
  let missingHandled = false;
  try { await resolveGhostBox("did:plc:nobodyhere0000000000000000", mockFetch); }
  catch { missingHandled = true; }
  check("unpublished identity fails cleanly", missingHandled);

  if (failures.length) { console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`); process.exit(1); }
  console.log(`\nAll ${pass} bridge checks passed (AT Proto discovery -> GhostBox private message, logic verified offline).`);
}

main().catch((e) => { console.error(e); process.exit(1); });
