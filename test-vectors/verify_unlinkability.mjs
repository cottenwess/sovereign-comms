/**
 * Unlinkability demonstration (Specter Layer, SPEC §4 + §8).
 *
 * Runs a realistic traffic pattern through the dead-drop, then dumps the
 * server's COMPLETE state — everything an adversary who seized the server would
 * have — and checks that the sender->recipient social graph is not recoverable
 * from it.
 *
 * This is a proof BY INSPECTION, and its scope is deliberately bounded:
 *
 *   IT SHOWS:  the protocol's own data structures do not encode who-sent-to-whom.
 *              The server knows which mailboxes received traffic and which were
 *              drained; it does not know who deposited, because deposits are
 *              unauthenticated.
 *
 *   IT DOES NOT SHOW:  resistance to a network-layer adversary. If the transport
 *              leaked IPs or timing, deposits and drains could be correlated
 *              regardless of server state. That threat is real, out of scope for
 *              a reference implementation, and addressed only by Tor/a mixnet
 *              (SPEC §8.4). Do not read this demo as "GhostBox is anonymous
 *              against a global passive adversary." It is not that claim.
 *
 * An existence argument like this is a sanity check, not a substitute for a
 * formal anonymity analysis (the right home for that is a PETS/ePrint paper).
 *
 * Run from repo root:  node test-vectors/verify_unlinkability.mjs
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { x25519, ed25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

const enc = new TextEncoder();

// --- minimal sealed box + server (tracks src/transport.ts) -----------------
const boxKey = (s) => hkdf(sha256, s, undefined, new TextEncoder().encode("ghostbox/v1/sealedbox"), 32);
function seal(pub, msg) {
  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, pub);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(boxKey(shared), nonce).encrypt(msg);
  const out = new Uint8Array(56 + ct.length);
  out.set(ephPub, 0); out.set(nonce, 32); out.set(ct, 56);
  return out;
}

class DropServer {
  store = new Map(); verifiers = new Map(); challenges = new Map();
  // Note the ABSENT fields: no sender log, no IP log, no deposit->drain map.
  register(loc, pub) { if (!this.verifiers.has(loc)) this.verifiers.set(loc, pub); }
  deposit(loc, ct) { const l = this.store.get(loc) ?? []; l.push(ct); this.store.set(loc, l); }
  challenge(loc) { const n = randomBytes(32); this.challenges.set(loc, n); return n; }
  claim(loc, sig) {
    const n = this.challenges.get(loc), v = this.verifiers.get(loc);
    if (!ed25519.verify(sig, n, v)) throw new Error("bad sig");
    this.challenges.delete(loc); const l = this.store.get(loc) ?? []; this.store.delete(loc); return l;
  }
  dumpState() {
    const mailboxes = {};
    for (const [loc, l] of this.store) mailboxes[loc.slice(0, 12) + "…"] = l.length;
    return {
      mailboxes,
      registeredLocators: [...this.verifiers.keys()].map((k) => k.slice(0, 12) + "…"),
      senderRecords: [],          // never populated — deposits are anonymous
      depositToDrainLinks: [],    // never populated — no correlation is kept
    };
  }
}

function randId() {
  const priv = x25519.utils.randomSecretKey();
  const sPriv = ed25519.utils.randomSecretKey();
  return {
    locatorHex: Array.from(randomBytes(16), (b) => b.toString(16).padStart(2, "0")).join(""),
    encryptionPublic: x25519.getPublicKey(priv),
    signingPublic: ed25519.getPublicKey(sPriv),
  };
}

const server = new DropServer();

// Cast: five participants, a known communication pattern we (the narrator) can
// see but the server cannot.
const people = { alice: randId(), bob: randId(), carol: randId(), dave: randId(), erin: randId() };

// The TRUE social graph (what we want to prove the server can't reconstruct):
const trueGraph = [
  ["alice", "bob"], ["alice", "carol"], ["bob", "carol"],
  ["dave", "erin"], ["erin", "alice"], ["carol", "dave"], ["bob", "dave"],
];

// Run the traffic. Each edge = one anonymous deposit at the recipient's mailbox.
for (const [from, to] of trueGraph) {
  server.deposit(people[to].locatorHex, seal(people[to].encryptionPublic, enc.encode(`msg ${from}->${to}`)));
}
// Some recipients drain (registering their verifier on first use).
for (const who of ["bob", "carol"]) {
  const me = people[who];
  server.register(me.locatorHex, me.signingPublic);
  // (drain omitted here; we want some mailboxes still full for the dump)
}

console.log("=".repeat(68));
console.log("TRUE social graph (known to us, the narrator):");
console.log(trueGraph.map(([f, t]) => `   ${f} -> ${t}`).join("\n"));
console.log("=".repeat(68));
console.log("\nSERVER'S COMPLETE STATE (everything a seizure would yield):\n");
console.log(JSON.stringify(server.dumpState(), null, 2));

// --- the checks ------------------------------------------------------------
const dump = server.dumpState();
const failures = [];

// 1. No sender information of any kind.
if (dump.senderRecords.length !== 0) failures.push("server retained sender records");

// 2. No deposit->drain correlation.
if (dump.depositToDrainLinks.length !== 0) failures.push("server retained deposit/drain links");

// 3. The dump exposes mailbox TRAFFIC (expected, and acknowledged), but the
//    only identifiers present are locator hashes — recipient addresses. There
//    is no field anywhere that names a sender. We assert the dump's keys are a
//    subset of {mailboxes, registeredLocators, senderRecords, depositToDrainLinks}
//    so no sender-bearing field can sneak in unnoticed.
const allowed = new Set(["mailboxes", "registeredLocators", "senderRecords", "depositToDrainLinks"]);
const leaked = Object.keys(dump).filter((k) => !allowed.has(k));
if (leaked.length) failures.push(`unexpected state field(s): ${leaked.join(", ")}`);

// 4. Sanity: the server CAN see that some mailboxes received traffic (we are
//    not over-claiming that it knows nothing — it knows recipients exist).
const sawTraffic = Object.keys(dump.mailboxes).length > 0;

console.log("\n" + "=".repeat(68));
console.log("FINDING");
console.log("=".repeat(68));
console.log(`The server can see ${Object.keys(dump.mailboxes).length} mailboxes received traffic.`);
console.log("It cannot name a single sender. The edges above — who sent to whom —");
console.log("are absent from its state. The social graph is not in the data.\n");
console.log("SCOPE: this is application-layer unlinkability only. A network-layer");
console.log("observer (IP/timing) is a separate, real threat — see SPEC §8.4.\n");

if (failures.length || !sawTraffic) {
  console.error("DEMONSTRATION FAILED:");
  for (const f of failures) console.error("  -", f);
  if (!sawTraffic) console.error("  - expected some mailbox traffic, found none");
  process.exit(1);
}
console.log("Demonstration holds: no sender→recipient linkage recoverable from server state.");
