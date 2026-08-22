#!/usr/bin/env node
// Copy the deploy verifier's non-.ts runtime assets into the built package (WRDF-0098).
// `tsc` emits only JavaScript; registry-config.js resolves the hash-pinned Jupiter IDL
// relative to its own dist location, so the IDL must be copied to dist/deploy/idl. The
// copy is HASH-VERIFIED against the same pin the verifier enforces, so a corrupted asset
// fails the build rather than shipping.
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG = join(dirname(fileURLToPath(import.meta.url)), "..");
const ASSETS = [
  { rel: "deploy/idl/jupiter-v6.idl.json", sha256: "764ea6d71b77458fd33aeb308d6e6bb19e660fc5320c5359f3b9cac96eba5c50" },
];

for (const a of ASSETS) {
  const src = join(PKG, "src", a.rel);
  const dst = join(PKG, "dist", a.rel);
  const bytes = readFileSync(src);
  const got = createHash("sha256").update(bytes).digest("hex");
  if (got !== a.sha256) {
    process.stderr.write(`copy-deploy-assets: ${a.rel} sha256 ${got} != pinned ${a.sha256}\n`);
    process.exit(1);
  }
  mkdirSync(dirname(dst), { recursive: true });
  writeFileSync(dst, bytes);
  process.stdout.write(`copied ${a.rel} (sha256 ${a.sha256.slice(0, 12)}…) → dist\n`);
}
