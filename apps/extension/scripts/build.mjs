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

const popupResult = await build({
  entryPoints: { popup: join(appDirectory, "src/popup/main.ts") },
  outdir: outputDirectory,
  format: "iife",
  ...sharedBuildOptions,
});

const approvalResult = await build({
  entryPoints: { approval: join(appDirectory, "src/approval/main.ts") },
  outdir: outputDirectory,
  format: "iife",
  ...sharedBuildOptions,
});

// C9 deliberately composes only the exact-byte review projector into the
// worker. Keep the approval coordinator, authority/RPC owners, signer, and
// release registry tree-shaken until a later milestone opens those capabilities
// with their own executable contracts.
const backgroundInputs = new Set(
  Object.keys(backgroundResult.metafile.inputs).map((input) => resolve(input)),
);
const requiredBackgroundInputs = [
  join(appDirectory, "src/background/approval-port.ts"),
  resolve(appDirectory, "../../packages/core/src/transaction/session-intent.ts"),
].map((input) => resolve(input));
const forbiddenBackgroundInputs = [
  "session-approval-coordinator.ts",
  "session-authority-resolver.ts",
  "session-release.ts",
  "session-rpc.ts",
  "session-transaction.ts",
].map((name) => resolve(
  appDirectory,
  `../../packages/core/src/transaction/${name}`,
));
const missingBackgroundInputs = requiredBackgroundInputs.filter(
  (input) => !backgroundInputs.has(input),
);
const reachableForbiddenInputs = forbiddenBackgroundInputs.filter(
  (input) => backgroundInputs.has(input),
);
if (missingBackgroundInputs.length > 0 || reachableForbiddenInputs.length > 0) {
  throw new Error(
    `background approval composition changed: missing=${missingBackgroundInputs.join(",")} forbidden=${reachableForbiddenInputs.join(",")}`,
  );
}

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

const allowedPopupInputs = [
  join(appDirectory, "src/popup/main.ts"),
  join(appDirectory, "src/popup-protocol.ts"),
].map((input) => resolve(input)).sort();
const popupInputs = Object.keys(popupResult.metafile.inputs)
  .map((input) => resolve(input))
  .sort();
if (
  popupInputs.length !== allowedPopupInputs.length ||
  popupInputs.some((input, index) => input !== allowedPopupInputs[index])
) {
  throw new Error(`popup dependency boundary changed: ${popupInputs.join(", ")}`);
}

// The full-page review surface consumes only primitive protocol responses. It
// must never bundle core decoders, approval storage, keyring, signing, RPC, or
// provider code; those remain background-only trust boundaries.
const allowedApprovalInputs = [
  join(appDirectory, "src/approval/main.ts"),
  join(appDirectory, "src/approval-protocol.ts"),
].map((input) => resolve(input)).sort();
const approvalInputs = Object.keys(approvalResult.metafile.inputs)
  .map((input) => resolve(input))
  .sort();
if (
  approvalInputs.length !== allowedApprovalInputs.length ||
  approvalInputs.some((input, index) => input !== allowedApprovalInputs[index])
) {
  throw new Error(`approval-page dependency boundary changed: ${approvalInputs.join(", ")}`);
}

for (const result of [backgroundResult, contentResult, popupResult, approvalResult]) {
  for (const output of Object.values(result.metafile.outputs)) {
    if (output.imports.some((entry) => entry.external)) {
      throw new Error("extension build contains an external runtime import");
    }
  }
}

await copyFile(join(appDirectory, "manifest.json"), join(outputDirectory, "manifest.json"));
await copyFile(join(appDirectory, "popup.html"), join(outputDirectory, "popup.html"));
await copyFile(join(appDirectory, "approval.html"), join(outputDirectory, "approval.html"));
await copyFile(join(appDirectory, "approval.css"), join(outputDirectory, "approval.css"));
const manifest = JSON.parse(await readFile(join(outputDirectory, "manifest.json"), "utf8"));
if (manifest.background?.service_worker !== "background.js") {
  throw new Error("extension manifest does not name the emitted background worker");
}
if (manifest.action?.default_popup !== "popup.html") {
  throw new Error("extension manifest does not name the emitted popup page");
}
const approvalHtml = await readFile(join(outputDirectory, "approval.html"), "utf8");
if (
  !approvalHtml.includes('<link rel="stylesheet" href="approval.css">') ||
  !approvalHtml.includes('<script src="approval.js"></script>') ||
  /<script(?:\s[^>]*)?>\s*[^<\s]/i.test(approvalHtml) ||
  /\son[a-z]+\s*=/i.test(approvalHtml)
) {
  throw new Error("approval page does not use only emitted local script/style assets");
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
