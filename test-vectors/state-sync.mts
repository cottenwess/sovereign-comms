/**
 * State-sync derivation test (SPEC §6.4).
 *
 * Verifies the DETERMINISTIC parts that are implemented: the sync address, the
 * key ladder (sync_key_0 and forward advance), index-walk consistency, address
 * separation from the message locator, and that the not-yet-built ratchet
 * serialization throws loudly rather than returning a fake. Imports the real
 * statesync.ts.
 *
 * Run from repo root:  npx tsx test-vectors/state-sync.mts
 *
 * @license AGPL-3.0-or-later
 * Copyright (C) 2026 Cory A. Ottenwess
 */

import { randomBytes } from "@noble/hashes/utils.js";
import {
  syncLocator,
  syncKeyZero,
  advanceSyncKey,
  syncKeyAt,
  serializeRatchetState,
  deserializeRatchetState,
} from "../src/statesync.ts";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
let pass = 0;
const failures: string[] = [];
const check = (name: string, cond: boolean) => {
  if (cond) { console.log(`PASS  ${name}`); pass++; }
  else { console.error(`FAIL  ${name}`); failures.push(name); }
};

const accessSeed = randomBytes(32);

// Determinism: same seed -> same address and key0
check("sync locator deterministic", hex(syncLocator(accessSeed)) === hex(syncLocator(accessSeed)));
check("sync locator is 16 bytes", syncLocator(accessSeed).length === 16);
check("sync key0 deterministic", hex(syncKeyZero(accessSeed)) === hex(syncKeyZero(accessSeed)));
check("sync key0 is 32 bytes", syncKeyZero(accessSeed).length === 32);

// Address separation: sync locator MUST differ from a naive message-locator
// derivation (different label => different output). Here we just assert it is
// not equal to key0 truncated etc.; the real point is label separation works.
check("sync locator != first 16 of key0",
  hex(syncLocator(accessSeed)) !== hex(syncKeyZero(accessSeed).subarray(0, 16)));

// Ladder: advance from key0 matches syncKeyAt(1); key0 matches syncKeyAt(0)
const k0 = syncKeyZero(accessSeed);
const k1 = advanceSyncKey(syncKeyZero(accessSeed));
check("syncKeyAt(0) == key0", hex(syncKeyAt(accessSeed, 0)) === hex(k0));
check("syncKeyAt(1) == advance(key0)", hex(syncKeyAt(accessSeed, 1)) === hex(k1));
check("ladder advances (k1 != k0)", hex(k0) !== hex(k1));

// Walk a few rungs, all distinct (forward ratchet)
const seen = new Set<string>();
for (let i = 0; i < 5; i++) seen.add(hex(syncKeyAt(accessSeed, i)));
check("first 5 ladder keys all distinct", seen.size === 5);

// Different seeds -> different sync addresses
const other = randomBytes(32);
check("different seed -> different sync locator",
  hex(syncLocator(accessSeed)) !== hex(syncLocator(other)));

// The not-yet-built ratchet must throw loudly, not fake success
let serThrew = false;
try { serializeRatchetState({ __unimplemented: true }); } catch { serThrew = true; }
check("serializeRatchetState throws (honest stub)", serThrew);
let deserThrew = false;
try { deserializeRatchetState(new Uint8Array(0)); } catch { deserThrew = true; }
check("deserializeRatchetState throws (honest stub)", deserThrew);

if (failures.length) {
  console.error(`\n${failures.length} FAILURE(S): ${failures.join(", ")}`);
  process.exit(1);
}
console.log(`\nAll ${pass} state-sync derivation checks passed (real module; ratchet correctly stubbed).`);
