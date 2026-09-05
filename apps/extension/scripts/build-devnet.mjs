import { build } from "esbuild";
import { createHash } from "node:crypto";
import { readFile, mkdir, copyFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve, join } from "node:path";

const app = fileURLToPath(new URL("..", import.meta.url));
const root = resolve(app, "../..");
const output = join(app, "dist/devnet");
// Explicit, fixed local artifact. This script never builds/deploys a program,
// reads a keypair, changes production settings, or writes a live website.
const binary = await readFile(join(root, "target/deploy/warden.so"));
if (binary.subarray(0, 4).toString("hex") !== "7f454c46") throw new Error("Expected a built Warden ELF at target/deploy/warden.so");
const pin = { sha256: createHash("sha256").update(binary).digest("hex"), bytes: binary.length };
await mkdir(join(output, "site/test"), { recursive: true });
await mkdir(join(output, "extension"), { recursive: true });
const options = { bundle: true, platform: "browser", target: "chrome120", format: "iife", sourcemap: false,
  legalComments: "none", absWorkingDir: app, metafile: true,
  alias: { "@warden/core/devnet": join(root, "packages/core/src/devnet.ts") } };
for (const name of ["background", "wallet", "site"]) {
  const result = await build({ ...options, entryPoints: [join(app, `src/devnet/${name}.ts`)],
    outfile: join(output, name === "site" ? "site/test/test.js" : `extension/${name}.js`),
    define: { __DEVNET_PROGRAM_PIN__: JSON.stringify(pin) } });
  for (const input of Object.keys(result.metafile.inputs)) {
    if (/spikes\/|\/test\/|src\/background\/|expected-keyring-context|registry-default/.test(input)) throw new Error(`Unexpected devnet bundle input: ${input}`);
  }
}
const manifest = { manifest_version: 3, name: "Warden DEVNET TEST", version: "0.0.1", minimum_chrome_version: "120",
  description: "Experimental passkey wallet test. Solana devnet only. Never use real funds.",
  permissions: ["storage"], host_permissions: ["https://api.devnet.solana.com/*"],
  background: { service_worker: "background.js" }, action: { default_title: "Open Warden devnet test wallet" },
  externally_connectable: { matches: ["https://wardenwallet.io/*", "http://localhost/*", "http://127.0.0.1/*"] },
  content_security_policy: { extension_pages: "default-src 'self'; script-src 'self'; object-src 'none'; connect-src https://api.devnet.solana.com; base-uri 'none'; frame-ancestors 'none'" } };
await writeFile(join(output, "extension/manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
await writeFile(join(output, "program-pin.json"), JSON.stringify(pin, null, 2) + "\n");
await copyFile(join(app, "devnet/wallet.html"), join(output, "extension/wallet.html"));
await copyFile(join(app, "devnet/test/index.html"), join(output, "site/test/index.html"));
await copyFile(join(app, "devnet/test.css"), join(output, "extension/test.css"));
await copyFile(join(app, "devnet/test.css"), join(output, "site/test/test.css"));
await copyFile(join(root, "docs/design/brand/landing-v3.html"), join(output, "site/index.html"));
console.log(`Devnet extension: ${join(output, "extension")}\nTest site: ${join(output, "site")}\nProgram SHA-256: ${pin.sha256} (${pin.bytes} bytes)`);
