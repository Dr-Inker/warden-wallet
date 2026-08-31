import type { ApprovalCreateParams, ApprovalRecord } from "@warden/core/approval";

import { ApprovalOwner } from "../src/background/approval-owner.js";
import { IndexedDbApprovalRecordRepository } from "../src/background/approval-store.js";
import {
  installApprovalWindowOwner,
  type ApprovalChromeWindow,
  type ApprovalWindowCreateData,
  type ApprovalWindowsApi,
} from "../src/background/approval-window.js";

interface InspectableChromeWindow extends ApprovalChromeWindow {
  readonly type?: string;
  readonly focused?: boolean;
  readonly width?: number;
  readonly height?: number;
}

interface BrowserWindowsApi extends ApprovalWindowsApi {
  getAll(options: {
    readonly populate: false;
    readonly windowTypes: readonly ["popup"];
  }): Promise<InspectableChromeWindow[]>;
}

interface BrowserChromeApi {
  readonly runtime: {
    readonly id: string;
    getManifest(): { readonly permissions?: unknown };
  };
  readonly windows: BrowserWindowsApi;
}

const chromeApi = (globalThis as unknown as { readonly chrome: BrowserChromeApi }).chrome;
const repository = new IndexedDbApprovalRecordRepository({
  databaseName: "warden-approval-window-browser-contract-v1",
});
const owner = new ApprovalOwner(repository);
const ready = owner.invalidateAfterWorkerRestart();
const fatals: string[] = [];
const createCalls: ApprovalWindowCreateData[] = [];
const measuredWindows: ApprovalWindowsApi = {
  onRemoved: chromeApi.windows.onRemoved,
  create(options) {
    createCalls.push(Object.freeze({ ...options }));
    return chromeApi.windows.create(options);
  },
  get(windowId) {
    return chromeApi.windows.get(windowId);
  },
  remove(windowId) {
    return chromeApi.windows.remove(windowId);
  },
};
const windows = installApprovalWindowOwner(measuredWindows, {
  runtimeId: chromeApi.runtime.id,
  approvals: owner,
  ready,
  onFatal: (error) => {
    fatals.push(error instanceof Error ? `${error.name}: ${error.message}` : String(error));
  },
});

const REQUEST_ID = `req_${"9a".repeat(16)}`;

function clearRecord(record: ApprovalRecord | null | undefined): void {
  record?.account.fill(0);
  record?.genesisHash.fill(0);
  record?.programId.fill(0);
  record?.rawMessage.fill(0);
  record?.messageDigest.fill(0);
}

function input(now: number): ApprovalCreateParams {
  return {
    id: REQUEST_ID,
    origin: "https://approval-window-browser.example",
    tabId: 7,
    frameId: 0,
    documentId: "approval-window-browser-document",
    account: new Uint8Array(32).fill(0x11),
    method: "solana:signTransaction",
    chain: "solana:devnet",
    genesisHash: new Uint8Array(32).fill(0x22),
    programId: new Uint8Array(32).fill(0x33),
    rawMessage: Uint8Array.of(1, 2, 3, 4),
    policyVersion: 1,
    createdAt: now,
    expiresAt: now + 60_000,
  };
}

async function openApprovalWindow() {
  await ready;
  const now = Date.now();
  const created = await owner.create(input(now));
  clearRecord(created);
  await windows.launch(REQUEST_ID, new AbortController().signal);
  const popups = await chromeApi.windows.getAll({
    populate: false,
    windowTypes: ["popup"],
  });
  return {
    requestId: REQUEST_ID,
    permissions: chromeApi.runtime.getManifest().permissions ?? [],
    createCalls: createCalls.map((options) => ({ ...options })),
    popups: popups.map((window) => ({
      id: window.id,
      type: window.type,
      focused: window.focused,
      width: window.width,
      height: window.height,
    })),
    fatals: [...fatals],
  };
}

async function readApprovalState(id: string) {
  const record = await owner.read(id);
  try {
    return {
      state: record?.state ?? null,
      fatals: [...fatals],
    };
  } finally {
    clearRecord(record);
  }
}

Object.assign(globalThis, {
  // This source is bundled only by approval-window.pw.ts into a temporary
  // extension. It is neither imported by nor copied into the product build.
  __wardenApprovalWindowOpen: openApprovalWindow,
  __wardenApprovalWindowRead: readApprovalState,
});
