//! Runnable maintenance script — the SOLE writer of the cross-language golden
//! fixtures. Run it deliberately when a fixture's definition changes:
//!
//!   pnpm --filter @warden/core gen:fixtures
//!
//! It only writes when executed AS the entry module (a real ESM main-module
//! check), never on import — the deterministic definitions live in the
//! side-effect-free `fixtures-data.ts`, which tests import without any
//! filesystem effect (WRDF-0081).

import { pathToFileURL } from "node:url";
import { generate } from "./fixtures-data.js";

// True only when this file is the process entry point (`tsx gen-fixtures.ts`),
// false when some other module imports it.
const isMain = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) generate();
