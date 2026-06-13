/**
 * GhostBox Protocol — AT Protocol bridge (ecosystem integration)
 *
 * Connects AT Protocol identity to GhostBox transport. The two systems solve
 * non-overlapping problems and compose cleanly:
 *
 *   AT Proto answers  "who is this person, and how do I find them"
 *   GhostBox answers  "how do I talk to them privately"
 *
 * The bridge publishes a small PUBLIC record in an AT Proto repo — a GhostBox
 * locator hash + X25519 public key — so that anyone who can resolve a handle
 * (@you.bsky.social -> DID -> record) can discover a GhostBox address. The
 * actual conversation then runs over the GhostBox dead-drop (src/transport.ts),
 * encrypted and unlinkable, never touching the AT Proto network. AT Proto does
 * the introduction; GhostBox does the private conversation.
 *
 * ─────────────────────────────────────────────────────────────────────────
 *  PRIVACY TRADEOFF — READ THIS. It is the whole point of being honest.
 * ─────────────────────────────────────────────────────────────────────────
 * Publishing a locator in a public AT Proto record makes the ASSOCIATION
 * between your public handle and your GhostBox address public and, in practice,
 * PERMANENT: AT Proto repos are publicly synced and archived via the firehose,
 * so a published locator may persist in archives even after you delete it.
 *
 * What stays private: message CONTENTS and the social graph of WHO YOU MESSAGE
 * (that is the dead-drop's job, and it still holds — see verify_unlinkability).
 * What becomes public: the fact that you use GhostBox, and which locator,
 * bound to your real handle.
 *
 * Therefore this bridge is for the FINDABLE case — a creator or public figure
 * who wants to be privately reachable. It is the WRONG tool for someone whose
 * goal is that their very presence on GhostBox stay hidden; that is the
 * Corporeal Layer's unlisted / proximity-only mode (SPEC §5.4), which must NOT
 * publish this record. Rotating to a fresh locator is the only mitigation once
 * an association is public. Do not publish a locator you need to stay secret.
 * ─────────────────────────────────────────────────────────────────────────
 *
 * Scope of this reference: it implements the did:plc resolution path
 * (plc.directory -> DID document -> PDS endpoint -> getRecord), which covers
 * the common Bluesky case. did:web and the full handle-resolution flow (DNS
 * TXT / .well-known) have additional cases noted inline. Production code may
 * prefer the official @atproto/api library; this stays dependency-light so the
 * discovery mechanism is legible to a reader.
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import type { SendTarget } from "./transport.js";

// The custom Lexicon this record conforms to. Schema in lexicons/com.ghostbox.identity.json
export const GHOSTBOX_NSID = "com.ghostbox.identity";
export const GHOSTBOX_RKEY = "self"; // one record per repo (literal:self key)

const hexToBytes = (h: string): Uint8Array => {
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) {
    throw new Error("invalid hex string");
  }
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
};

// ===========================================================================
//  The record shape (conforms to com.ghostbox.identity)
// ===========================================================================

export interface GhostBoxIdentityRecord {
  readonly $type: typeof GHOSTBOX_NSID;
  /** GhostBox Locator Hash, hex. Public deposit address. */
  readonly locatorHash: string;
  /** X25519 public key, hex. Others encrypt sealed-box messages to this. */
  readonly encryptionPublicKey: string;
  /** Protocol version this address was minted under. */
  readonly protocolVersion: string;
  /** ISO 8601 timestamp. */
  readonly createdAt: string;
}

/** Build a publishable record from the PUBLIC fields of a GhostBox identity. */
export function buildIdentityRecord(
  locatorHex: string,
  encryptionPublicHex: string,
  protocolVersion = "ghostbox/0.3",
): GhostBoxIdentityRecord {
  return {
    $type: GHOSTBOX_NSID,
    locatorHash: locatorHex,
    encryptionPublicKey: encryptionPublicHex,
    protocolVersion,
    createdAt: new Date().toISOString(),
  };
}

// ===========================================================================
//  Resolution: DID -> DID document -> PDS endpoint -> record -> SendTarget
// ===========================================================================

type FetchLike = (url: string, init?: unknown) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

export interface ResolveOptions {
  /** Inject a fetch implementation (used for offline tests). Defaults to global fetch. */
  readonly fetchImpl?: FetchLike;
  /** PLC directory base. Defaults to the public directory. */
  readonly plcDirectory?: string;
}

interface DidDocument {
  id: string;
  service?: Array<{ id: string; type: string; serviceEndpoint: string }>;
}

/** Resolve a did:plc to its DID document via the PLC directory (SPEC: AT Proto identity). */
export async function resolveDidDocument(
  did: string,
  opts: ResolveOptions = {},
): Promise<DidDocument> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) throw new Error("no fetch implementation available");

  if (did.startsWith("did:plc:")) {
    const base = opts.plcDirectory ?? "https://plc.directory";
    const res = await fetchImpl(`${base}/${did}`);
    if (!res.ok) throw new Error(`PLC directory returned ${res.status} for ${did}`);
    return (await res.json()) as DidDocument;
  }
  if (did.startsWith("did:web:")) {
    // did:web:example.com -> https://example.com/.well-known/did.json
    const host = did.slice("did:web:".length).replace(/:/g, "/");
    const res = await fetchImpl(`https://${host}/.well-known/did.json`);
    if (!res.ok) throw new Error(`did:web host returned ${res.status} for ${did}`);
    return (await res.json()) as DidDocument;
  }
  throw new Error(`unsupported DID method: ${did}`);
}

/** Extract the AT Proto PDS endpoint from a DID document. */
export function extractPdsEndpoint(doc: DidDocument): string {
  const svc = doc.service?.find(
    (s) => s.type === "AtprotoPersonalDataServer" || s.id === "#atproto_pds",
  );
  if (!svc?.serviceEndpoint) {
    throw new Error("DID document has no AtprotoPersonalDataServer endpoint");
  }
  return svc.serviceEndpoint.replace(/\/$/, "");
}

/** Fetch the GhostBox identity record from a PDS via com.atproto.repo.getRecord. */
export async function fetchGhostBoxRecord(
  pdsEndpoint: string,
  did: string,
  opts: ResolveOptions = {},
): Promise<GhostBoxIdentityRecord> {
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  if (!fetchImpl) throw new Error("no fetch implementation available");

  const url =
    `${pdsEndpoint}/xrpc/com.atproto.repo.getRecord` +
    `?repo=${encodeURIComponent(did)}` +
    `&collection=${encodeURIComponent(GHOSTBOX_NSID)}` +
    `&rkey=${encodeURIComponent(GHOSTBOX_RKEY)}`;

  const res = await fetchImpl(url);
  if (!res.ok) {
    throw new Error(
      `getRecord returned ${res.status} — no GhostBox identity published for ${did}?`,
    );
  }
  const body = (await res.json()) as { value?: GhostBoxIdentityRecord };
  if (!body.value || body.value.$type !== GHOSTBOX_NSID) {
    throw new Error("record exists but is not a com.ghostbox.identity record");
  }
  return body.value;
}

/**
 * Top-level: resolve an AT Proto DID to a GhostBox SendTarget you can message.
 * This is the bridge — "I know their Bluesky DID" becomes "I can send them a
 * private GhostBox message."
 *
 * Note: this takes a DID, not a handle. Handle->DID resolution (DNS TXT
 * `_atproto.<handle>` or `https://<handle>/.well-known/atproto-did`) is a
 * separate first step; resolve the handle, then call this. Kept separate so the
 * record-resolution logic is testable without DNS.
 */
export async function resolveGhostBoxIdentity(
  did: string,
  opts: ResolveOptions = {},
): Promise<SendTarget> {
  const doc = await resolveDidDocument(did, opts);
  const pds = extractPdsEndpoint(doc);
  const record = await fetchGhostBoxRecord(pds, did, opts);
  return {
    locatorHex: record.locatorHash,
    encryptionPublic: hexToBytes(record.encryptionPublicKey),
  };
}

// ===========================================================================
//  Publishing — request shape only (live write needs YOUR credentials)
// ===========================================================================
//
// Writing a record needs an authenticated session, which this reference does
// not handle (never put credentials in library code). Instead it builds the
// exact com.atproto.repo.putRecord request; you run it with your own auth.
// See README "Publishing your GhostBox identity" for the runnable steps.

export interface PutRecordRequest {
  readonly endpoint: string; // POST here, with Authorization: Bearer <accessJwt>
  readonly body: {
    repo: string;
    collection: string;
    rkey: string;
    record: GhostBoxIdentityRecord;
  };
}

/** Build the putRecord request to publish your GhostBox identity to your PDS. */
export function buildPutRecordRequest(
  pdsEndpoint: string,
  did: string,
  record: GhostBoxIdentityRecord,
): PutRecordRequest {
  return {
    endpoint: `${pdsEndpoint.replace(/\/$/, "")}/xrpc/com.atproto.repo.putRecord`,
    body: {
      repo: did,
      collection: GHOSTBOX_NSID,
      rkey: GHOSTBOX_RKEY,
      record,
    },
  };
}

export { hexToBytes };
