/**
 * Integration test — Spirit Layer (identity) + Specter Layer (transport).
 *
 * Imports the REAL modules (src/identity.ts, src/transport.ts) and drives the
 * dead-drop with genuinely derived identities. No reimplementation: a divergence
 * between the modules and this test surfaces here.
 *
 * Verifies: derive -> deposit -> challenge/sign/claim -> decrypt round-trips,
 * plus the negatives that carry the security story (wrong signer can't drain; a
 * third party can't decrypt another's blob).
 *
 * Run from repo root:  npx tsx test-vectors/integration.mts
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  deriveIdentity,
  textFactor,
  hashedFactor,
  toHex,
  type Identity,
} from "../src/identity.ts";
import {
  DropServer,
  sendMessage,
  receiveMessages,
  seal,
  unseal,
  type ReceiveIdentity,
} from "../src/transport.ts";

const te = new TextEncoder();
const dg = (s: string) => sha256(te.encode(s));

let pass = 0;
const failures: string[] = [];
const check = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

// Strong, distinct identities via the advanced API (one know + three hashed).
function person(tag: string): Promise<Identity> {
  return deriveIdentity([
    textFactor(`${tag} correct horse battery staple plenitude`),
    hashedFactor("have", dg(`${tag}-token`), 64, "yubikey-hmac"),
    hashedFactor("who", dg(`${tag}-contact`), 64, "ssi-vc"),
    hashedFactor("are", dg(`${tag}-bio`), 24, "fido2-prf"),
  ]);
}

const asReceiver = (id: Identity): ReceiveIdentity => ({
  locatorHex: toHex(id.locatorHash),
  signingPrivate: id.signingPrivate,
  signingPublic: id.signingPublic,
  encryptionPrivate: id.encryptionPrivate,
});
const asTarget = (id: Identity) => ({
  locatorHex: toHex(id.locatorHash),
  encryptionPublic: id.encryptionPublic,
});

const alice = await person("alice");
const bob = await person("bob");
const carol = await person("carol");

check("distinct locators", new Set([
  toHex(alice.locatorHash), toHex(bob.locatorHash), toHex(carol.locatorHash),
]).size === 3);

const server = new DropServer();

// Alice -> Bob, Carol -> Bob
sendMessage(server, asTarget(bob), "hello bob, it's alice");
sendMessage(server, asTarget(bob), "bob, carol here");

const bobMsgs = receiveMessages(server, asReceiver(bob));
check("bob receives 2 messages", bobMsgs.length === 2);
check("bob reads alice's message", bobMsgs.includes("hello bob, it's alice"));
check("bob reads carol's message", bobMsgs.includes("bob, carol here"));

// Bob -> Alice
sendMessage(server, asTarget(alice), "got them, thanks");
const aliceMsgs = receiveMessages(server, asReceiver(alice));
check("alice receives reply", aliceMsgs.length === 1 && aliceMsgs[0] === "got them, thanks");

// NEGATIVE: a wrong signer cannot drain Bob's box
sendMessage(server, asTarget(bob), "second round");
server.register(toHex(bob.locatorHash), bob.signingPublic);
const nonce = server.challenge(toHex(bob.locatorHash));
let imposterBlocked = false;
try {
  server.claim(toHex(bob.locatorHash), ed25519.sign(nonce, carol.signingPrivate));
} catch {
  imposterBlocked = true;
}
check("imposter cannot drain another's mailbox", imposterBlocked);

// NEGATIVE: a third party cannot decrypt a blob addressed to Bob
const blobForBob = seal(bob.encryptionPublic, te.encode("secret for bob"));
let cannotDecrypt = false;
try {
  unseal(carol.encryptionPrivate, blobForBob);
} catch {
  cannotDecrypt = true;
}
check("third party cannot decrypt another's blob", cannotDecrypt);

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} integration checks passed (real Spirit + Specter modules).`);
