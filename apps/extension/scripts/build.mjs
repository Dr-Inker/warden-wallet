import { copyFile, mkdir, readFile, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const appDirectory = resolve(scriptDirectory, "..");
const outputDirectory = join(appDirectory, "dist");

if (resolve(outputDirectory) !== resolve(appDirectory, "dist")) {
  throw new Error("refusing to clean an unexpected extension output directory");
}
await rm(outputDirectory, { recursive: true, force: true });
await mkdir(outputDirectory, { recursive: true });
const result = await build({
  entryPoints: { background: join(appDirectory, "src/background/main.ts") },
  outdir: outputDirectory,
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "chrome102",
  sourcemap: false,
  legalComments: "none",
  metafile: true,
});

for (const output of Object.values(result.metafile.outputs)) {
  if (output.imports.some((entry) => entry.external)) {
    throw new Error("extension build contains an external runtime import");
  }
}

await copyFile(join(appDirectory, "manifest.json"), join(outputDirectory, "manifest.json"));
const manifest = JSON.parse(await readFile(join(outputDirectory, "manifest.json"), "utf8"));
if (manifest.background?.service_worker !== "background.js") {
  throw new Error("extension manifest does not name the emitted background worker");
}
