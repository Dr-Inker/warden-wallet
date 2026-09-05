import { chromium, expect, test, type Page } from "@playwright/test";
import { resolve } from "node:path";

const EXTENSION_DIRECTORY = resolve(import.meta.dirname, "../dist");
const FIRST = "FTPSf3Po3uMpD9KRxWZtaqM27t7zCR8k7oAgz22u2eEC";
const SECOND = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";

test("local onboarding saves, selects and removes accounts across a worker restart", async () => {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [`--disable-extensions-except=${EXTENSION_DIRECTORY}`, `--load-extension=${EXTENSION_DIRECTORY}`, "--headless=new"],
  });
  try {
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker");
    const origin = new URL(worker.url()).origin;
    // URL.origin is opaque for chrome-extension in Node; keep Chrome's exact scheme/host.
    const extensionOrigin = origin === "null" ? `chrome-extension://${new URL(worker.url()).hostname}` : origin;
    const page = await context.newPage();
    await page.goto(`${extensionOrigin}/popup.html`);
    await expect(page.locator("#accounts-status")).toHaveAttribute("data-state", "ready");
    await expect(page.locator("#accounts-welcome")).toBeVisible();
    const measurements: unknown[] = [];
    const measure = async (state: string): Promise<void> => {
      for (const width of [320, 360]) {
        await page.setViewportSize({ width, height: 600 });
        const metrics = await page.evaluate(() => ({
          viewport: document.documentElement.clientWidth,
          width: document.documentElement.scrollWidth,
          controls: Array.from(document.querySelectorAll("#saved-accounts button, #saved-accounts input, #saved-accounts select, #saved-accounts textarea"))
            .map((element) => ({ id: element.id, height: element.getBoundingClientRect().height }))
            .filter((control) => control.height > 0),
          addressFits: (() => {
            const element = document.querySelector("#account-address")!;
            return element.scrollWidth <= element.clientWidth;
          })(),
        }));
        expect(metrics.width).toBe(metrics.viewport);
        expect(metrics.addressFits).toBe(true);
        for (const control of metrics.controls) expect(control.height).toBeGreaterThanOrEqual(44);
        measurements.push({ state, requestedWidth: width, ...metrics });
        await page.screenshot({ path: test.info().outputPath(`accounts-${state}-${width}.png`), fullPage: true });
      }
    };
    await measure("welcome");
    await page.getByRole("button", { name: "Add public account" }).click();
    await page.getByLabel("Account name", { exact: true }).fill("Primary");
    await page.getByLabel("Solana public address", { exact: true }).fill("invalid-address");
    await page.getByRole("button", { name: "Save account", exact: true }).click();
    await expect(page.locator("#accounts-status")).toContainText("valid Solana public address");
    await page.getByLabel("Solana public address", { exact: true }).fill(FIRST);
    await measure("form");
    // Exercise form submission using only the keyboard.
    await page.getByRole("button", { name: "Save account", exact: true }).focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#account-address")).toHaveText(FIRST);
    await expect(page.locator("#account-select")).toBeFocused();
    await expect(page.getByText("Balance and ownership have not been checked.", { exact: false })).toBeVisible();
    await measure("saved");
    await addAccount(page, "Savings", SECOND);
    await expect(page.locator("#account-address")).toHaveText(SECOND);
    await page.getByLabel("Saved account", { exact: true }).selectOption(FIRST);
    await expect(page.locator("#accounts-status")).toHaveAttribute("data-state", "ready");
    await expect(page.locator("#account-address")).toHaveText(FIRST);

    const cdp = await context.newCDPSession(page);
    const targets = await cdp.send("Target.getTargets");
    const target = targets.targetInfos.find((item) => item.type === "service_worker" && item.url.startsWith(extensionOrigin));
    expect(target).toBeDefined();
    expect((await cdp.send("Target.closeTarget", { targetId: target!.targetId })).success).toBe(true);
    await expect.poll(async () => (await cdp.send("Target.getTargets")).targetInfos.some((item) => item.targetId === target!.targetId)).toBe(false);
    await page.reload();
    await expect(page.locator("#accounts-status")).toHaveAttribute("data-state", "ready");
    await expect(page.locator("#account-address")).toHaveText(FIRST);
    await expect(page.locator("#account-select option")).toHaveCount(2);

    await page.getByRole("button", { name: "Add public account" }).click();
    await page.getByLabel("Solana public address", { exact: true }).fill(FIRST);
    await page.getByRole("button", { name: "Save account", exact: true }).click();
    await expect(page.locator("#accounts-status")).toContainText("already saved");
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("button", { name: "Remove from this device" }).click();
    await page.getByRole("button", { name: "Keep account" }).click();
    await expect(page.locator("#account-select option")).toHaveCount(2);
    await page.getByRole("button", { name: "Remove from this device" }).click();
    await page.getByRole("button", { name: "Confirm removal" }).click();
    await expect(page.locator("#account-address")).toHaveText(SECOND);
    await page.getByRole("button", { name: "Remove from this device" }).click();
    await page.getByRole("button", { name: "Confirm removal" }).click();
    await expect(page.locator("#accounts-welcome")).toBeVisible();
    await page.reload();
    await expect(page.locator("#accounts-welcome")).toBeVisible();
    await test.info().attach("account-onboarding-measurements", { body: JSON.stringify(measurements, null, 2), contentType: "application/json" });
  } finally { await context.close(); }
});

async function addAccount(page: Page, label: string, address: string): Promise<void> {
  await page.getByRole("button", { name: "Add public account" }).click();
  await page.getByLabel("Account name", { exact: true }).fill(label);
  await page.getByLabel("Solana public address", { exact: true }).fill(address);
  await page.getByRole("button", { name: "Save account", exact: true }).click();
}
