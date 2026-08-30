import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: [
      {
        find: "@warden/core/approval",
        replacement: fileURLToPath(
          new URL("../../packages/core/src/approval/index.ts", import.meta.url),
        ),
      },
      {
        find: "@warden/core/constants",
        replacement: fileURLToPath(
          new URL("../../packages/core/src/constants.ts", import.meta.url),
        ),
      },
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
