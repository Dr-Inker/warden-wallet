import { cpus, platform, release, tmpdir, totalmem } from "node:os";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "@playwright/test";
import { build } from "esbuild";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const temporaryParent = resolve(tmpdir());
const extensionDirectory = await mkdtemp(
  join(temporaryParent, "warden-argon2-benchmark-"),
);
const expectedTemporaryPrefix = `${temporaryParent}${sep}warden-argon2-benchmark-`;
if (!resolve(extensionDirectory).startsWith(expectedTemporaryPrefix)) {
  throw new Error("Argon2 benchmark temporary directory escaped the expected parent");
}

let context;
try {
  await build({
    entryPoints: {
      background: join(scriptDirectory, "argon2-benchmark-worker.ts"),
    },
    outdir: extensionDirectory,
    bundle: true,
    platform: "browser",
    target: "chrome106",
    format: "esm",
    sourcemap: false,
    legalComments: "none",
  });
  await writeFile(
    join(extensionDirectory, "manifest.json"),
    `${JSON.stringify({
      manifest_version: 3,
      name: "Warden Argon2 Calibration",
      version: "0.0.0",
      background: {
        service_worker: "background.js",
        type: "module",
      },
      content_security_policy: {
        extension_pages: "script-src 'self'; object-src 'self'",
      },
    }, null, 2)}\n`,
    "utf8",
  );

  context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [
      `--disable-extensions-except=${extensionDirectory}`,
      `--load-extension=${extensionDirectory}`,
      "--headless=new",
    ],
  });
  const worker = context.serviceWorkers().find((candidate) =>
    candidate.url().startsWith("chrome-extension://")) ??
    await context.waitForEvent("serviceworker", {
      predicate: (candidate) => candidate.url().startsWith("chrome-extension://"),
      timeout: 30_000,
    });
  const measurement = await worker.evaluate(async () => {
    const runner = globalThis.__wardenArgon2Benchmark;
    if (typeof runner !== "function") {
      throw new Error("Argon2 benchmark worker entry point is unavailable");
    }
    return runner();
  });
  const processors = cpus();
  const result = {
    ...measurement,
    host: {
      platform: platform(),
      release: release(),
      cpuModel: processors[0]?.model ?? "unknown",
      logicalCpuCount: processors.length,
      totalMemoryBytes: totalmem(),
    },
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} finally {
  await context?.close();
  await rm(extensionDirectory, { recursive: true, force: true });
}
