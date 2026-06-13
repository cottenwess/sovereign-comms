/**
 * AT Proto bridge — offline integration test (imports the REAL modules).
 *
 * Proves the full integration LOGIC end to end with the network MOCKED:
 *   derive identity (Spirit, real module)
 *     -> build a com.ghostbox.identity record (real bridge module)
 *     -> "publish" it (mock PDS)
 *     -> resolve it back: DID -> DID doc -> PDS -> record -> SendTarget
 *     -> send a private message (real transport) -> drain -> decrypt
 *
 * The live AT Proto network is NOT exercised (sandbox can't reach it; a real
 * publish needs credentials). The bridge logic is verified here against a mocked
 * network; run the live path per README "Publishing your GhostBox identity".
 *
 * Run from repo root:  npx tsx test-vectors/atproto-bridge.mts
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
import { DropServer, sendMessage, unseal } from "../src/transport.ts";
import {
  buildIdentityRecord,
  resolveGhostBoxIdentity,
  GHOSTBOX_NSID,
  GHOSTBOX_RKEY,
} from "../src/atproto-bridge.ts";

const te = new TextEncoder();
const dec = new TextDecoder();
const dg = (s: string) => sha256(te.encode(s));

let pass = 0;
const failures: string[] = [];
const check = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

const bob: Identity = await deriveIdentity([
  textFactor("bob correct horse battery staple plenitude"),
  hashedFactor("have", dg("bob-token"), 64, "yubikey-hmac"),
  hashedFactor("who", dg("bob-contact"), 64, "ssi-vc"),
  hashedFactor("are", dg("bob-bio"), 24, "fido2-prf"),
]);

const bobDid = "did:plc:examplebob1234567890abcd";
const bobPds = "https://pds.example.com";
const record = buildIdentityRecord(toHex(bob.locatorHash), toHex(bob.encryptionPublic));

check("record has correct $type", record.$type === GHOSTBOX_NSID);
check("record carries bob's locator", record.locatorHash === toHex(bob.locatorHash));

// Mock AT Proto network: a PLC DID doc + a getRecord response.
const network: Record<string, unknown> = {
  [`https://plc.directory/${bobDid}`]: {
    id: bobDid,
    alsoKnownAs: ["at://bob.example.com"],
    service: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer", serviceEndpoint: bobPds }],
  },
  [`${bobPds}/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(bobDid)}&collection=${GHOSTBOX_NSID}&rkey=${GHOSTBOX_RKEY}`]: {
    uri: `at://${bobDid}/${GHOSTBOX_NSID}/${GHOSTBOX_RKEY}`,
    value: record,
  },
};
const mockFetch = async (url: string) => {
  if (url in network) return { ok: true, status: 200, json: async () => network[url] };
  return { ok: false, status: 404, json: async () => ({}) };
};

// Alice resolves Bob's GhostBox address from his DID alone.
const target = await resolveGhostBoxIdentity(bobDid, { fetchImpl: mockFetch as never });
check("resolved locator matches bob", target.locatorHex === toHex(bob.locatorHash));
check("resolved key matches bob", toHex(target.encryptionPublic) === toHex(bob.encryptionPublic));

// Alice messages Bob privately over the dead-drop using only what she resolved.
const server = new DropServer();
sendMessage(server, target, "found you via AT Proto, here privately");

// Bob drains and decrypts.
server.register(toHex(bob.locatorHash), bob.signingPublic);
const nonce = server.challenge(toHex(bob.locatorHash));
const blobs = server.claim(toHex(bob.locatorHash), ed25519.sign(nonce, bob.signingPrivate));
const msgs = blobs.map((b) => dec.decode(unseal(bob.encryptionPrivate, b)));
check("bob receives the bridged message",
  msgs.length === 1 && msgs[0] === "found you via AT Proto, here privately");

// NEGATIVE: a DID with no record resolves to a clean failure.
let missingHandled = false;
try {
  await resolveGhostBoxIdentity("did:plc:nobodyhere0000000000000000", { fetchImpl: mockFetch as never });
} catch {
  missingHandled = true;
}
check("unpublished identity fails cleanly", missingHandled);

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} bridge checks passed (real modules; discovery -> private message).`);
