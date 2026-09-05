import { chromium, expect, test, type BrowserContext } from "@playwright/test";
import {
  createPendingApprovalRecord,
  type ApprovalRecord,
} from "@warden/core/approval";
import { resolve } from "node:path";

import {
  APPROVAL_DATABASE_NAME,
  APPROVAL_DATABASE_VERSION,
  APPROVAL_OBJECT_STORE_NAME,
} from "../src/background/approval-store.js";

test("review surface shows full origins and a usable development popup", async () => {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_DIRECTORY}`,
      `--load-extension=${EXTENSION_DIRECTORY}`,
      "--headless=new",
    ],
  });
  try {
    const worker = await liveExtensionWorker(context);
    const extensionOrigin = `chrome-extension://${new URL(worker.url()).hostname}`;
    const longOrigin = "https://wallet.accounts.customer-support.trusted-looking-name.attacker.example:8443";
    const record = approval("fa", 120_000, longOrigin);
    await seedRecord(worker, record);
    const page = await context.newPage();
    await page.goto(`${extensionOrigin}/approval.html?request=${record.id}`);
    await expect(page.locator("#approval-status")).toHaveAttribute("data-state", "review");
    await expect(page.locator("#request-origin")).toHaveText(longOrigin);
    await expect(page.getByRole("region", { name: "Review evidence" })).toBeVisible();
    await expect(page.getByText("Not run. Network effects have not been simulated.")).toBeVisible();
    await expect(page.getByText("Not evaluated here. A policy version is not a limits check.")).toBeVisible();
    const measurements: unknown[] = [];
    for (const width of [320, 360, 720]) {
      await page.setViewportSize({ width, height: 900 });
      const metrics = await page.locator("#request-origin").evaluate((element) => {
        const box = element.getBoundingClientRect();
        const range = document.createRange();
        range.selectNodeContents(element);
        return {
          originWidth: element.clientWidth,
          originScrollWidth: element.scrollWidth,
          documentWidth: document.documentElement.scrollWidth,
          viewportWidth: document.documentElement.clientWidth,
          lineCount: range.getClientRects().length,
          everyLineVisible: Array.from(range.getClientRects()).every((rect) =>
            rect.left >= box.left - 1 && rect.right <= box.right + 1 &&
            rect.top >= box.top - 1 && rect.bottom <= box.bottom + 1),
        };
      });
      expect(metrics.originScrollWidth).toBeLessThanOrEqual(metrics.originWidth);
      expect(metrics.documentWidth).toBe(width);
      expect(metrics.lineCount).toBeGreaterThan(1);
      expect(metrics.everyLineVisible).toBe(true);
      measurements.push({ surface: "approval", width, ...metrics });
      await page.screenshot({ path: test.info().outputPath(`full-origin-${width}.png`), fullPage: true });
    }

    // Prove the measurement rejects the previous ellipsis presentation. A DOM
    // toHaveText assertion alone would pass both presentations.
    await page.setViewportSize({ width: 320, height: 900 });
    await page.locator("#request-origin").evaluate((element) => {
      element.style.whiteSpace = "nowrap";
      element.style.overflow = "hidden";
      element.style.textOverflow = "ellipsis";
    });
    expect(await page.locator("#request-origin").evaluate((element) =>
      element.scrollWidth > element.clientWidth)).toBe(true);

    await page.goto(`${extensionOrigin}/popup.html`);
    await expect(page.locator("#boundary-status")).toHaveAttribute("data-boundary", "unavailable");
    const retry = page.getByRole("button", { name: "Check again" });
    await retry.focus();
    await page.keyboard.press("Enter");
    await expect(retry).toBeEnabled();
    await expect(page.locator("#boundary-status")).toHaveAttribute("data-boundary", "unavailable");
    for (const width of [320, 360]) {
      await page.setViewportSize({ width, height: 600 });
      const metrics = await page.evaluate(() => ({
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: document.documentElement.clientWidth,
        retryHeight: document.querySelector("#retry-status")!.getBoundingClientRect().height,
        contentBottom: document.querySelector(".popup-shell")!.getBoundingClientRect().bottom,
      }));
      expect(metrics.documentWidth).toBe(width);
      expect(metrics.retryHeight).toBeGreaterThanOrEqual(44);
      expect(metrics.contentBottom).toBeLessThanOrEqual(600);
      measurements.push({ surface: "popup", width, ...metrics });
      await page.screenshot({ path: test.info().outputPath(`popup-${width}.png`), fullPage: true });
    }
    await page.getByText("What can I try?", { exact: true }).focus();
    await page.keyboard.press("Enter");
    await expect(page.locator(".popup-guide")).toHaveAttribute("open", "");
    await expect(page.getByText("Account setup", { exact: true })).toBeVisible();
    await test.info().attach("review-surface-measurements", {
      body: JSON.stringify(measurements, null, 2), contentType: "application/json",
    });
  } finally {
    await context.close();
  }
});

const EXTENSION_DIRECTORY = resolve(import.meta.dirname, "../dist");
const SMART_ACCOUNT = "FTPSf3Po3uMpD9KRxWZtaqM27t7zCR8k7oAgz22u2eEC";
const SESSION_SIGNER = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
// Static account key 2 in GOLDEN_MESSAGE_HEX; deliberately not obtained from
// the review projector under test.
const SESSION_ACCOUNT = "8YYgCkVsKgpEf9ygpBbfXUpbc9s6xjgxPotFWE9gipnv";
const REGISTRY = "DcKmSgbaMzGX1ERKPXCADMtSKYypWxWCDfPsi27nA3ga";
const WARDEN_PROGRAM = "6nX7pb3j5NTebXnP3dqCcxniRe7fJqwvfNi461g4Dm2";
const MEMO_PROGRAM = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const GENESIS_HASH = "BLbDu5FZUdSfLrGejhuaWw5iMJBo3j3TVRyPv9rfJyMA";
const RECENT_BLOCKHASH = "AByCTxLPRZPoyK22KdMxa3xkCbcNbeNWzVeEvh6UcJs9";
const SMART_ACCOUNT_BYTES = Uint8Array.from(Buffer.from(
  "d6c617f8f9b6efa8f53b8e3519b87ce86c0d4b8bf97da710769c395d7a6225f9",
  "hex",
));
const WARDEN_PROGRAM_BYTES = Uint8Array.from(Buffer.from(
  "017b5f72e2c074fa8555206db7ccf465c1db513c725913ca7ce685f135f8bd51",
  "hex",
));
const GOLDEN_MESSAGE_HEX =
  "80010004072222222222222222222222222222222222222222222222222222222222222222" +
  "d6c617f8f9b6efa8f53b8e3519b87ce86c0d4b8bf97da710769c395d7a6225f97016a12" +
  "f469df2029c389bc4a61caf34c1e8f290b01d1971bd12853c70b6a49b0306466fe521173" +
  "2ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000017b5f72e2c074fa855520" +
  "6db7ccf465c1db513c725913ca7ce685f135f8bd51bb58ca5e9f58c81171d832ad015248" +
  "304e438e6b9a0ab891f53c5286275046f7054a535a992921064d24e87160da387c7c35b5" +
  "ddbc92bb81e41fa8404105448d888888888888888888888888888888888888888888888888" +
  "88888888888888880303000502c02709000300050100000200040801000204040504062b82" +
  "ddf29a0dc1bd1d00011d000000010200180077617264656e2072656c656173652063616e64" +
  "696461746500";

async function liveExtensionWorker(context: BrowserContext) {
  const current = [...context.serviceWorkers()].reverse().find((worker) =>
    worker.url().startsWith("chrome-extension://"));
  if (current !== undefined) return current;
  return context.waitForEvent("serviceworker", {
    predicate: (worker) => worker.url().startsWith("chrome-extension://"),
    timeout: 30_000,
  });
}

function approval(idByte: string, ttlMs = 120_000, origin = "https://dapp.example"): ApprovalRecord {
  const now = Date.now();
  return createPendingApprovalRecord({
    id: `req_${idByte.repeat(16)}`,
    origin,
    tabId: 7,
    frameId: 0,
    documentId: `browser-provider-${idByte}`,
    account: SMART_ACCOUNT_BYTES,
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: new Uint8Array(32).fill(0x99),
    programId: WARDEN_PROGRAM_BYTES,
    rawMessage: Uint8Array.from(Buffer.from(GOLDEN_MESSAGE_HEX, "hex")),
    policyVersion: 1,
    createdAt: now,
    expiresAt: now + ttlMs,
  });
}

function portable(record: ApprovalRecord): Record<string, unknown> {
  return {
    ...record,
    account: Array.from(record.account),
    genesisHash: Array.from(record.genesisHash),
    programId: Array.from(record.programId),
    rawMessage: Array.from(record.rawMessage),
    messageDigest: Array.from(record.messageDigest),
  };
}

async function seedRecord(
  worker: Awaited<ReturnType<typeof liveExtensionWorker>>,
  record: ApprovalRecord,
): Promise<void> {
  await worker.evaluate(async ({ databaseName, databaseVersion, objectStoreName, value }) => {
    const database = await new Promise<IDBDatabase>((resolveOpen, rejectOpen) => {
      const request = indexedDB.open(databaseName, databaseVersion);
      request.onerror = () => rejectOpen(
        request.error ?? new Error("approval review database open failed"),
      );
      request.onsuccess = () => resolveOpen(request.result);
    });
    try {
      const approval = {
        ...value,
        account: new Uint8Array(value.account as number[]),
        genesisHash: new Uint8Array(value.genesisHash as number[]),
        programId: new Uint8Array(value.programId as number[]),
        rawMessage: new Uint8Array(value.rawMessage as number[]),
        messageDigest: new Uint8Array(value.messageDigest as number[]),
      };
      await new Promise<void>((resolveWrite, rejectWrite) => {
        const transaction = database.transaction(objectStoreName, "readwrite", {
          durability: "strict",
        });
        transaction.oncomplete = () => resolveWrite();
        transaction.onabort = () => rejectWrite(
          transaction.error ?? new Error("approval review seed aborted"),
        );
        transaction.onerror = () => {};
        transaction.objectStore(objectStoreName).add({
          id: value.id,
          approval,
          signing: null,
        });
      });
    } finally {
      database.close();
    }
  }, {
    databaseName: APPROVAL_DATABASE_NAME,
    databaseVersion: APPROVAL_DATABASE_VERSION,
    objectStoreName: APPROVAL_OBJECT_STORE_NAME,
    value: portable(record),
  });
}

async function readState(
  worker: Awaited<ReturnType<typeof liveExtensionWorker>>,
  id: string,
): Promise<string | null> {
  return worker.evaluate(async ({ databaseName, databaseVersion, objectStoreName, id }) => {
    const database = await new Promise<IDBDatabase>((resolveOpen, rejectOpen) => {
      const request = indexedDB.open(databaseName, databaseVersion);
      request.onerror = () => rejectOpen(
        request.error ?? new Error("approval review database open failed"),
      );
      request.onsuccess = () => resolveOpen(request.result);
    });
    try {
      return await new Promise<string | null>((resolveRead, rejectRead) => {
        const transaction = database.transaction(objectStoreName, "readonly");
        const request = transaction.objectStore(objectStoreName).get(id);
        request.onerror = () => rejectRead(
          request.error ?? new Error("approval review read failed"),
        );
        request.onsuccess = () => {
          const result = request.result as {
            readonly approval?: { readonly state?: unknown };
          } | undefined;
          resolveRead(typeof result?.approval?.state === "string"
            ? result.approval.state
            : null);
        };
      });
    } finally {
      database.close();
    }
  }, {
    databaseName: APPROVAL_DATABASE_NAME,
    databaseVersion: APPROVAL_DATABASE_VERSION,
    objectStoreName: APPROVAL_OBJECT_STORE_NAME,
    id,
  });
}

test("approval page renders exact bytes and terminalizes navigation/rejection races", async () => {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_DIRECTORY}`,
      `--load-extension=${EXTENSION_DIRECTORY}`,
      "--headless=new",
    ],
  });
  try {
    const worker = await liveExtensionWorker(context);
    const extensionOrigin = `chrome-extension://${new URL(worker.url()).hostname}`;

    const navigated = approval("a1");
    await seedRecord(worker, navigated);
    const reviewPage = await context.newPage();
    await reviewPage.setViewportSize({ width: 720, height: 900 });
    await reviewPage.goto(
      `${extensionOrigin}/approval.html?request=${navigated.id}`,
    );
    await expect(reviewPage.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "review",
    );
    await expect(reviewPage.locator("#request-origin")).toHaveText(
      "https://dapp.example",
    );
    await expect(reviewPage.locator("#memo-value")).toHaveText(
      "warden release candidate",
    );
    await expect(reviewPage.locator("#network-value")).toHaveText("Solana Devnet");
    await expect(reviewPage.locator("#account-value")).toHaveText(
      SMART_ACCOUNT,
    );
    await expect(reviewPage.locator("#digest-value")).toHaveText(
      Buffer.from(navigated.messageDigest).toString("hex"),
    );
    await expect(reviewPage.locator("[data-action=approve]")).toBeDisabled();
    const technicalDetails = reviewPage.locator("#technical-details");
    await expect(technicalDetails).not.toHaveAttribute("open", "");
    const detailsSummary = technicalDetails.locator("summary");
    await expect(detailsSummary).toHaveText("Technical details");
    expect((await detailsSummary.boundingBox())?.height).toBeGreaterThanOrEqual(44);
    await reviewPage.screenshot({
      path: test.info().outputPath("approval-review-collapsed-desktop.png"),
      fullPage: true,
    });
    await detailsSummary.focus();
    await expect(detailsSummary).toBeFocused();
    await reviewPage.keyboard.press("Enter");
    await expect(technicalDetails).toHaveAttribute("open", "");
    await expect(reviewPage.locator("#session-signer-value")).toHaveText(SESSION_SIGNER);
    await expect(reviewPage.locator("#session-account-value")).toHaveText(SESSION_ACCOUNT);
    await expect(reviewPage.locator("#registry-value")).toHaveText(REGISTRY);
    await expect(reviewPage.locator("#warden-program-value")).toHaveText(WARDEN_PROGRAM);
    await expect(reviewPage.locator("#memo-program-value")).toHaveText(MEMO_PROGRAM);
    await expect(reviewPage.locator("#genesis-hash-value")).toHaveText(GENESIS_HASH);
    await expect(reviewPage.locator("#recent-blockhash-value")).toHaveText(RECENT_BLOCKHASH);
    await expect(reviewPage.locator("#compute-limit-value")).toHaveText("600,000 units");
    await expect(reviewPage.locator("#heap-frame-value")).toHaveText("131,072 bytes");
    await expect(reviewPage.locator("#message-size-value")).toHaveText(
      "333 message bytes · 24 memo bytes",
    );
    const desktopLayout = await reviewPage.evaluate(() => {
      const shell = document.querySelector<HTMLElement>(".shell")!.getBoundingClientRect();
      const reject = document.querySelector<HTMLButtonElement>("[data-action=reject]")!
        .getBoundingClientRect();
      return {
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: document.documentElement.clientWidth,
        shellLeft: shell.left,
        shellRight: shell.right,
        rejectHeight: reject.height,
      };
    });
    expect(desktopLayout.documentWidth).toBe(desktopLayout.viewportWidth);
    expect(desktopLayout.shellLeft).toBeGreaterThanOrEqual(0);
    expect(desktopLayout.shellRight).toBeLessThanOrEqual(desktopLayout.viewportWidth);
    expect(desktopLayout.rejectHeight).toBeGreaterThanOrEqual(44);
    await reviewPage.screenshot({
      path: test.info().outputPath("approval-review-desktop.png"),
      fullPage: true,
    });

    await reviewPage.setViewportSize({ width: 390, height: 844 });
    const mobileLayout = await reviewPage.evaluate(() => {
      const reject = document.querySelector<HTMLButtonElement>("[data-action=reject]")!
        .getBoundingClientRect();
      const approve = document.querySelector<HTMLButtonElement>("[data-action=approve]")!
        .getBoundingClientRect();
      return {
        documentWidth: document.documentElement.scrollWidth,
        viewportWidth: document.documentElement.clientWidth,
        rejectHeight: reject.height,
        approveHeight: approve.height,
        rejectBottom: reject.bottom,
        approveTop: approve.top,
      };
    });
    expect(mobileLayout.documentWidth).toBe(mobileLayout.viewportWidth);
    expect(mobileLayout.rejectHeight).toBeGreaterThanOrEqual(44);
    expect(mobileLayout.approveHeight).toBeGreaterThanOrEqual(44);
    expect(mobileLayout.approveTop).toBeGreaterThan(mobileLayout.rejectBottom);
    await reviewPage.screenshot({
      path: test.info().outputPath("approval-review-mobile.png"),
      fullPage: true,
    });
    await reviewPage.goto("about:blank");
    await expect.poll(() => readState(worker, navigated.id)).toBe("cancelled");

    const rejected = approval("b2");
    await seedRecord(worker, rejected);
    const rejectionPage = await context.newPage();
    await rejectionPage.goto(
      `${extensionOrigin}/approval.html?request=${rejected.id}`,
    );
    await expect(rejectionPage.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "review",
    );
    await rejectionPage.locator("[data-action=reject]").click();
    await expect(rejectionPage.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "rejected",
    );
    await expect.poll(() => readState(worker, rejected.id)).toBe("rejected");
    await rejectionPage.close();

    const raced = approval("c3");
    await seedRecord(worker, raced);
    const racePage = await context.newPage();
    await racePage.goto(`${extensionOrigin}/approval.html?request=${raced.id}`);
    await expect(racePage.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "review",
    );
    await Promise.allSettled([
      racePage.locator("[data-action=reject]").click(),
      racePage.close(),
    ]);
    await expect.poll(() => readState(worker, raced.id)).toMatch(/^(rejected|cancelled)$/);
  } finally {
    await context.close();
  }
});

test("approval page visibly expires and terminalizes the durable record", async () => {
  const context = await chromium.launchPersistentContext("", {
    headless: false,
    args: [
      `--disable-extensions-except=${EXTENSION_DIRECTORY}`,
      `--load-extension=${EXTENSION_DIRECTORY}`,
      "--headless=new",
    ],
  });
  try {
    const worker = await liveExtensionWorker(context);
    const extensionOrigin = `chrome-extension://${new URL(worker.url()).hostname}`;
    const expiring = approval("d4", 3_000);
    await seedRecord(worker, expiring);
    const page = await context.newPage();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(`${extensionOrigin}/approval.html?request=${expiring.id}`);
    await expect(page.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "review",
    );
    await expect(page.locator("#expiry-countdown")).toContainText("Expires in");
    await expect(page.locator("#approval-status")).toHaveAttribute(
      "data-state",
      "expired",
      { timeout: 7_000 },
    );
    await expect(page.locator("#approval-status")).toHaveText(
      "Request expired. No signature was produced.",
    );
    await expect(page.locator("[data-action=reject]")).toBeDisabled();
    await expect(page.locator("[data-action=approve]")).toBeDisabled();
    await expect.poll(() => readState(worker, expiring.id)).toBe("expired");
    await page.screenshot({
      path: test.info().outputPath("approval-review-expired-mobile.png"),
      fullPage: true,
    });
  } finally {
    await context.close();
  }
});
