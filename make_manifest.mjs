#!/usr/bin/env node
/**
 * make_manifest.mjs — regenerate MANIFEST.json from the current tree.
 *
 * Run AFTER you have made and verified changes, so the baseline reflects the new
 * correct state:
 *     node make_manifest.mjs
 *
 * Then commit MANIFEST.json alongside your changes. The next session's
 * `node verify_manifest.mjs` will check against this updated baseline.
 *
 * Excludes node_modules, .git, __pycache__, package-lock.json (churns), and
 * MANIFEST.json itself.
 *
 * @license AGPL-3.0-or-later
 */
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const SKIP_DIRS = new Set(["node_modules", ".git", "__pycache__", "dist"]);
const SKIP_FILES = new Set(["MANIFEST.json", "package-lock.json"]);

function walk(dir, acc = []) {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const rel = p.replace(/^\.\//, "");
    if (SKIP_DIRS.has(entry)) continue;
    const st = statSync(p);
    if (st.isDirectory()) walk(p, acc);
    else if (!SKIP_FILES.has(entry) && !entry.endsWith(".orig")) acc.push(rel);
  }
  return acc;
}

const PROTOCOL_VERSION =
  JSON.parse(readFileSync("package.json", "utf8")).version ?? "unknown";

const files = walk(".").sort().map((path) => {
  const b = readFileSync(path);
  return {
    path,
    sha256: createHash("sha256").update(b).digest("hex"),
    bytes: b.length,
    lines: b.length ? b.toString("utf8").split("\n").length : 0,
  };
});

const manifest = {
  manifest_version: 1,
  protocol_version: PROTOCOL_VERSION,
  generated: new Date().toISOString().slice(0, 10),
  purpose:
    "Source-of-truth integrity manifest. Before extending the repo in any session, verify your working files against these SHA-256 hashes with verify_manifest.mjs. A mismatch means your baseline is stale or diverged - resolve that BEFORE building, or you will repeat the cross-language drift that v0.3.1 fixed.",
  files,
};

writeFileSync("MANIFEST.json", JSON.stringify(manifest, null, 2) + "\n");
console.log(`MANIFEST.json regenerated: ${files.length} files, protocol v${PROTOCOL_VERSION}`);
