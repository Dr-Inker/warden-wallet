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
        find: "@warden/core/transaction/session-approval",
        replacement: fileURLToPath(
          new URL(
            "../../packages/core/src/transaction/session-approval-coordinator.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@warden/core/transaction/session-release",
        replacement: fileURLToPath(
          new URL(
            "../../packages/core/src/transaction/session-release.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@warden/core/transaction/session-rpc",
        replacement: fileURLToPath(
          new URL(
            "../../packages/core/src/transaction/session-rpc.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@warden/core/transaction/session-intent",
        replacement: fileURLToPath(
          new URL(
            "../../packages/core/src/transaction/session-intent.ts",
            import.meta.url,
          ),
        ),
      },
      {
        find: "@warden/core",
        replacement: fileURLToPath(new URL("../../packages/core/src/index.ts", import.meta.url)),
      },
    ],
  },
});
