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
const sharedBuildOptions = {
  bundle: true,
  platform: "browser",
  target: "chrome106",
  sourcemap: false,
  legalComments: "none",
  metafile: true,
};

const backgroundResult = await build({
  entryPoints: { background: join(appDirectory, "src/background/main.ts") },
  outdir: outputDirectory,
  format: "esm",
  ...sharedBuildOptions,
});

const contentResult = await build({
  entryPoints: { content: join(appDirectory, "src/content/main.ts") },
  outdir: outputDirectory,
  format: "iife",
  ...sharedBuildOptions,
});

// Keep the page-reachable bundle structurally thin. A future import of a
// background, storage, keyring, RPC, approval, or broad core module must fail
// here and receive an explicit threat-model review before this allowlist grows.
const allowedContentInputs = [
  join(appDirectory, "src/content/main.ts"),
  join(appDirectory, "src/content/bridge.ts"),
  join(appDirectory, "src/provider-protocol.ts"),
].map((input) => resolve(input)).sort();
const contentInputs = Object.keys(contentResult.metafile.inputs)
  .map((input) => resolve(input))
  .sort();
if (
  contentInputs.length !== allowedContentInputs.length ||
  contentInputs.some((input, index) => input !== allowedContentInputs[index])
) {
  throw new Error(
    `content-script dependency boundary changed: ${contentInputs.join(", ")}`,
  );
}

for (const result of [backgroundResult, contentResult]) {
  for (const output of Object.values(result.metafile.outputs)) {
    if (output.imports.some((entry) => entry.external)) {
      throw new Error("extension build contains an external runtime import");
    }
  }
}

await copyFile(join(appDirectory, "manifest.json"), join(outputDirectory, "manifest.json"));
const manifest = JSON.parse(await readFile(join(outputDirectory, "manifest.json"), "utf8"));
if (manifest.background?.service_worker !== "background.js") {
  throw new Error("extension manifest does not name the emitted background worker");
}
const contentScripts = Array.isArray(manifest.content_scripts)
  ? manifest.content_scripts
  : [];
if (
  contentScripts.length !== 1 ||
  !Array.isArray(contentScripts[0]?.js) ||
  contentScripts[0].js.length !== 1 ||
  contentScripts[0].js[0] !== "content.js"
) {
  throw new Error("extension manifest does not name the emitted content script");
}
