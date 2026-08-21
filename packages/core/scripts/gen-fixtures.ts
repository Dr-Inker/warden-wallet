//! Runnable maintenance script — the SOLE writer of the cross-language golden
//! fixtures. Run it deliberately when a fixture's definition changes:
//!
//!   pnpm --filter @warden/core gen:fixtures
//!
//! It writes ONLY when executed AS the entry module (a real ESM main-module
//! check), never on import. The deterministic definitions live in the
//! side-effect-free `fixtures-data.ts` (no `node:fs`), so tests import them with
//! zero filesystem effect; the `write` sink here is injectable so a test can
//! exercise the generation logic without touching disk (WRDF-0081).

import { mkdirSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { FIXTURES_DIR, goldenContents } from "./fixtures-data.js";

/** The default sink: write each named golden into `FIXTURES_DIR`. */
const writeToDisk = (name: string, data: Uint8Array | string): void => {
  mkdirSync(FIXTURES_DIR, { recursive: true });
  writeFileSync(resolve(FIXTURES_DIR, name), data);
};

/**
 * Emit every golden through `write` (default: to disk). Returns the file names
 * emitted. Passing a collecting sink lets a test verify the generation logic and
 * bytes WITHOUT any filesystem write.
 */
export function generate(write: (name: string, data: Uint8Array | string) => void = writeToDisk): string[] {
  const contents = goldenContents();
  for (const [name, data] of Object.entries(contents)) write(name, data);
  return Object.keys(contents);
}

/** True only when this file is the process entry point (`tsx gen-fixtures.ts`). */
export const ranAsMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (ranAsMain) {
  const names = generate();
  // eslint-disable-next-line no-console
  console.log(`wrote ${names.length} fixtures to ${FIXTURES_DIR}`);
}
