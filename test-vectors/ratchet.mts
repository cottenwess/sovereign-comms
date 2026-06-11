/**
 * Symmetric-key ratchet test (SPEC §6.2) — imports the real src/ratchet.ts.
 *
 * Verifies the properties that matter:
 *   - two parties derive the SAME root and MIRRORED chains from a triple-DH
 *   - in-order messaging works in both directions
 *   - out-of-order / batched delivery works via skipped keys
 *   - send and receive keys for the same message number MATCH (the chains line up)
 *   - forward secrecy: advancing a chain forgets the prior key (keys differ per step)
 *   - the MAX_SKIP cap throws RatchetSkipLimitError
 *
 * Run from repo root:  npx tsx test-vectors/ratchet.mts
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { x25519 } from "@noble/curves/ed25519.js";
import { randomBytes } from "@noble/hashes/utils.js";
import {
  initRatchet,
  deriveRoot,
  ratchetSend,
  ratchetReceive,
  RatchetSkipLimitError,
  MAX_SKIP,
  type HandshakeInput,
} from "../src/ratchet.ts";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
let pass = 0;
const failures: string[] = [];
const check = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

// --- set up two parties with identity + ephemeral keypairs -----------------
function kp() {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv) };
}
const aliceId = kp(), aliceEph = kp();
const bobId = kp(), bobEph = kp();

const aliceHS: HandshakeInput = {
  idPrivate: aliceId.priv, idPublic: aliceId.pub,
  ephPrivate: aliceEph.priv, ephPublic: aliceEph.pub,
  peerIdPublic: bobId.pub, peerEphPublic: bobEph.pub,
};
const bobHS: HandshakeInput = {
  idPrivate: bobId.priv, idPublic: bobId.pub,
  ephPrivate: bobEph.priv, ephPublic: bobEph.pub,
  peerIdPublic: aliceId.pub, peerEphPublic: aliceEph.pub,
};

// 1. Both parties derive the SAME root (canonical ordering works).
check("triple-DH roots agree", hex(deriveRoot(aliceHS)) === hex(deriveRoot(bobHS)));

const alice = initRatchet(aliceHS);
const bob = initRatchet(bobHS);

// 2. Alice's send chain == Bob's receive chain (mirrored).
//    Test via actual message-key agreement below rather than peeking keys.

// 3. In-order: Alice -> Bob, three messages, send/recv keys match.
let inOrderOk = true;
for (let i = 0; i < 3; i++) {
  const { messageKey: sk, header } = ratchetSend(alice);
  const rk = ratchetReceive(bob, header);
  if (hex(sk) !== hex(rk)) inOrderOk = false;
}
check("in-order A->B message keys match", inOrderOk);

// 4. Reverse direction independently: Bob -> Alice.
let reverseOk = true;
for (let i = 0; i < 2; i++) {
  const { messageKey: sk, header } = ratchetSend(bob);
  const rk = ratchetReceive(alice, header);
  if (hex(sk) !== hex(rk)) reverseOk = false;
}
check("in-order B->A message keys match", reverseOk);

// 5. Forward secrecy: consecutive message keys on a chain are all distinct.
const a2 = initRatchet(aliceHS);
const keys = new Set<string>();
for (let i = 0; i < 5; i++) keys.add(hex(ratchetSend(a2).messageKey));
check("consecutive message keys all distinct (forward secrecy)", keys.size === 5);

// 6. Out-of-order / batched: Alice sends 5; Bob receives them shuffled.
const a3 = initRatchet(aliceHS);
const b3 = initRatchet(bobHS);
const sent: { key: string; header: { messageNumber: number } }[] = [];
for (let i = 0; i < 5; i++) {
  const { messageKey, header } = ratchetSend(a3);
  sent.push({ key: hex(messageKey), header });
}
// deliver in order 2,0,4,1,3
let oooOk = true;
for (const idx of [2, 0, 4, 1, 3]) {
  const rk = hex(ratchetReceive(b3, sent[idx]!.header));
  if (rk !== sent[idx]!.key) oooOk = false;
}
check("out-of-order delivery resolves correct keys", oooOk);

// 7. A consumed message number cannot be replayed.
let replayRejected = false;
try { ratchetReceive(b3, sent[0]!.header); } catch { replayRejected = true; }
check("consumed message number cannot be reused", replayRejected);

// 8. Skip cap: a gap larger than MAX_SKIP throws RatchetSkipLimitError.
const a4 = initRatchet(aliceHS);
const b4 = initRatchet(bobHS);
let lastHeader = { messageNumber: 0 };
for (let i = 0; i <= MAX_SKIP + 1; i++) lastHeader = ratchetSend(a4).header;
let capThrew = false, rightType = false;
try {
  ratchetReceive(b4, lastHeader); // forces a gap of MAX_SKIP+1
} catch (e) {
  capThrew = true;
  rightType = e instanceof RatchetSkipLimitError;
}
check("skip cap exceeded throws", capThrew);
check("skip cap throws RatchetSkipLimitError", rightType);

// 9. Different pair -> different root (sanity).
const carolId = kp(), carolEph = kp();
const aliceCarolHS: HandshakeInput = {
  idPrivate: aliceId.priv, idPublic: aliceId.pub,
  ephPrivate: aliceEph.priv, ephPublic: aliceEph.pub,
  peerIdPublic: carolId.pub, peerEphPublic: carolEph.pub,
};
check("different peer -> different root",
  hex(deriveRoot(aliceHS)) !== hex(deriveRoot(aliceCarolHS)));

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} ratchet checks passed (symmetric ratchet, triple-DH, real module).`);
