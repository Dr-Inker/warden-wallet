import { chromium, expect, test } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

// Browser boundary/UX gate only. RPC is explicitly an ABSENT deployment.
// Real instruction execution belongs to cargo test --test devnet_client;
// neither test claims a live devnet deployment or a real hardware passkey.
test("devnet website opens an owned review, reports rejection, and exposes a missing deployment", async () => {
  test.setTimeout(60_000);
  execFileSync(process.execPath, [resolve(import.meta.dirname, "../scripts/build-devnet.mjs")]);
  const directory = resolve(import.meta.dirname, "../dist/devnet");
  const server = createServer((request, response) => {
    const path = new URL(request.url ?? "/", "http://localhost:4173").pathname;
    const files: Record<string, [string, string]> = {
      "/test/": ["index.html", "text/html"], "/test/test.js": ["test.js", "text/javascript"], "/test/test.css": ["test.css", "text/css"],
    };
    const file = files[path];
    if (!file) { response.writeHead(404).end(); return; }
    void readFile(resolve(directory, "site/test", file[0])).then(bytes => { response.writeHead(200, { "Content-Type": file[1] }); response.end(bytes); });
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(4173, "127.0.0.1", resolve); });
  const extension = resolve(directory, "extension");
  const context = await chromium.launchPersistentContext("", {
    headless: false, args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, "--headless=new"],
  });
  try {
    await context.route("https://api.devnet.solana.com/**", route => {
      const request = route.request().postDataJSON();
      const result = request.method === "getGenesisHash" ? "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG" :
        { context: { slot: 493700271 }, value: null };
      return route.fulfill({ contentType: "application/json", body: JSON.stringify({ jsonrpc: "2.0", id: request.id, result }) });
    });
    const worker = context.serviceWorkers()[0] ?? await context.waitForEvent("serviceworker");
    const id = new URL(worker.url()).hostname;
    const website = await context.newPage();
    await website.goto("http://127.0.0.1:4173/test/");
    await website.getByLabel("Devnet extension ID").fill(id);
    const reviewPromise = context.waitForEvent("page");
    await website.getByRole("button", { name: "Connect wallet", exact: true }).click();
    const review = await reviewPromise;
    await review.waitForLoadState("domcontentloaded");
    await expect(review.locator("#request-origin")).toHaveText("http://127.0.0.1:4173");
    await expect(review.locator("#status")).toContainText("not deployed on devnet");
    for (const page of [website, review]) {
      for (const width of [320, 360, 800]) {
        await page.setViewportSize({ width, height: 800 });
        const metrics = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, width: document.documentElement.scrollWidth,
          controls: Array.from(document.querySelectorAll("button,input")).map(e => e.getBoundingClientRect().height).filter(h => h > 0) }));
        expect(metrics.width).toBe(metrics.viewport);
        for (const height of metrics.controls) expect(height).toBeGreaterThanOrEqual(44);
        const name = `${page === website ? "site" : "review"}-${width}`;
        await test.info().attach(`${name}-metrics`, { body: JSON.stringify(metrics), contentType: "application/json" });
        await page.screenshot({ path: test.info().outputPath(`${name}.png`), fullPage: true });
      }
    }
    await review.getByRole("button", { name: "Reject", exact: true }).click();
    await expect(website.locator("#status")).toHaveText("User rejected the request");
    await expect(website.locator("#account")).toHaveText("Not connected");
    await expect(website.locator("#transaction")).toBeHidden();
  } finally {
    await context.close();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
