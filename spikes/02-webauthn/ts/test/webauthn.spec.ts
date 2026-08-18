import { test, expect, chromium } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const EXT = resolve(import.meta.dirname, "../../ext");

async function discoverExtensionId(ctx: import("@playwright/test").BrowserContext): Promise<string> {
  // Extension id discovery: chrome://extensions is unreachable under headless
  // Chrome-for-Testing (WebUI pages return net::ERR_INVALID_URL) and the CDP
  // Extensions.loadUnpacked method is not present in this Chromium build
  // either — both were tried and ruled out (see result.md). The reliable,
  // deterministic path is the one the brief sanctions as a fallback: give the
  // extension a trivial background.service_worker (ext/background.js) purely
  // so its id can be read off the registered ServiceWorker's origin.
  let sw = ctx.serviceWorkers()[0];
  if (!sw) sw = await ctx.waitForEvent("serviceworker", { timeout: 10_000 });
  return sw.url().split("/")[2];
}

test("ES256 + PRF create/get from extension origin", async () => {
  // NOTE: `headless: true` here (Playwright's own headless flag) conflicts with
  // the manual `--headless=new` arg below and silently prevents the unpacked
  // extension from loading (no error, just no serviceworker/popup ever
  // appears). Passing `headless: false` and letting `--headless=new` alone
  // drive headless mode is required — see result.md.
  const ctx = await chromium.launchPersistentContext("", {
    headless: false,
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, "--headless=new"],
  });

  const extId = await discoverExtensionId(ctx);

  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");

  let hasPrf = true;
  let authenticatorId: string;
  try {
    ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true,
      } as any,
    }));
  } catch {
    hasPrf = false;
    ({ authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
      options: {
        protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
        isUserVerified: true, automaticPresenceSimulation: true,
      } as any,
    }));
  }

  await page.goto(`chrome-extension://${extId}/popup.html`);
  await page.click("#create");
  await page.waitForFunction(() => (window as any).__spike);
  const created = JSON.parse((await page.textContent("#out")) ?? "{}");
  expect(created.alg).toBe(-7);

  await page.click("#get");
  await page.waitForFunction(() => (window as any).__assertion);
  const assertion = await page.evaluate(() => (window as any).__assertion);
  expect(assertion.origin.startsWith("chrome-extension://")).toBe(true);

  mkdirSync(resolve(import.meta.dirname, "../../out"), { recursive: true });
  writeFileSync(
    resolve(import.meta.dirname, "../../out/assertion.json"),
    JSON.stringify({ ...assertion, virtualAuthenticatorId: authenticatorId }, null, 2),
  );

  // Surface diagnostics in the test report for result.md.
  console.log("extensionId:", extId);
  console.log("hasPrf accepted by CDP:", hasPrf);
  console.log("create prfEnabled:", created.prfEnabled);
  console.log("assertion prfFirst present:", assertion.prfFirst !== null);

  await ctx.close();
});
