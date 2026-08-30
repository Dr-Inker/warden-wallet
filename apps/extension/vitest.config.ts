import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@warden/core/keyring",
        replacement: fileURLToPath(
          new URL("../../packages/core/src/keyring/index.ts", import.meta.url),
        ),
      },
      {
        find: "@warden/core",
        replacement: fileURLToPath(new URL("../../packages/core/src/index.ts", import.meta.url)),
      },
    ],
  },
});
