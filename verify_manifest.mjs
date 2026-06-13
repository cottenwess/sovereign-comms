#!/usr/bin/env node
/**
 * verify_manifest.mjs — baseline integrity check.
 *
 * Run this FIRST in any session before extending the repo:
 *     node verify_manifest.mjs
 *
 * It recomputes SHA-256 for every file in MANIFEST.json and reports drift.
 * A mismatch means your working copy differs from the recorded v0.3.1 baseline
 * — STOP and reconcile before building, or you risk layering work on a stale
 * tree (the exact failure mode that produced the cross-language drift fixed in
 * v0.3.1). New files not in the manifest are listed as additions (expected when
 * you are adding features); changed/missing files are flagged as drift.
 *
 * Exit 0 = clean (no drift). Exit 1 = drift found.
 *
 * @license AGPL-3.0-or-later
 */
import { readFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";

const manifest = JSON.parse(readFileSync("MANIFEST.json", "utf8"));
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");

let drift = 0;
const missing = [];
const changed = [];
for (const f of manifest.files) {
  if (f.path === "MANIFEST.json") continue;
  if (!existsSync(f.path)) { missing.push(f.path); drift++; continue; }
  if (sha(f.path) !== f.sha256) { changed.push(f.path); drift++; }
}

console.log(`Manifest: protocol v${manifest.protocol_version} (generated ${manifest.generated})`);
console.log(`Checked ${manifest.files.length} files.\n`);

if (missing.length) {
  console.error("MISSING (in manifest, not on disk):");
  for (const p of missing) console.error("  - " + p);
}
if (changed.length) {
  console.error("CHANGED (hash differs from baseline):");
  for (const p of changed) console.error("  ~ " + p);
}

if (drift === 0) {
  console.log("CLEAN — working copy matches the recorded baseline. Safe to build.");
  process.exit(0);
}
console.error(`\nDRIFT: ${drift} file(s) differ from the v${manifest.protocol_version} baseline.`);
console.error("Reconcile before extending the repo. If this drift is intentional");
console.error("(you just made changes), regenerate the manifest after verifying the changes are correct.");
process.exit(1);
