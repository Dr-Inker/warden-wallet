import { execFile as execFileCallback } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFile = promisify(execFileCallback);
const evidencePath = "docs/security/third-party/pnpm-licenses.json";
const lockHashPath = "docs/security/third-party/pnpm-lock.sha256";
const lockfilePath = "pnpm-lock.yaml";

const { stdout } = await execFile("pnpm", ["licenses", "list", "--json"], {
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});
JSON.parse(stdout);
await writeFile(evidencePath, stdout.endsWith("\n") ? stdout : `${stdout}\n`);

const lockfile = await readFile(lockfilePath);
const digest = createHash("sha256").update(lockfile).digest("hex");
await writeFile(lockHashPath, `${digest}  ${lockfilePath}\n`);
