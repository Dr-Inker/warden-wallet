import { describe, expect, it } from "vitest";

import {
  classifyPrivilegedUiSender,
  classifyProviderSender,
  SenderProvenanceError,
} from "../src/background/sender-provenance.js";

const EXTENSION_ID = "a".repeat(32);
const OTHER_EXTENSION_ID = "b".repeat(32);
const DOCUMENT_ID = "123e4567-e89b-12d3-a456-426614174000";

function providerSender(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    documentId: DOCUMENT_ID,
    documentLifecycle: "active",
    frameId: 0,
    id: EXTENSION_ID,
    origin: "https://dapp.example",
    tab: { id: 7, url: "https://dapp.example/top-level" },
    url: "https://dapp.example/wallet",
    ...overrides,
  };
}

function uiSender(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    documentId: DOCUMENT_ID,
    documentLifecycle: "active",
    id: EXTENSION_ID,
    origin: `chrome-extension://${EXTENSION_ID}`,
    url: `chrome-extension://${EXTENSION_ID}/popup.html`,
    ...overrides,
  };
}

describe("provider Port.sender provenance", () => {
  it("derives a frozen authority tuple only from browser-owned sender fields", () => {
    const result = classifyProviderSender({
      runtimeId: EXTENSION_ID,
      sender: providerSender({
        // A cross-origin child frame must not inherit the top-level tab URL.
        frameId: 4,
        origin: "https://iframe.example",
        tab: { id: 19, url: "https://host.example/parent" },
        url: "https://iframe.example/embedded?request=1",
        // Unneeded browser metadata is not copied into the authority tuple. This
        // pure classifier receives no page message, so payload stripping remains
        // a separate router obligation rather than a claim of this test.
        tlsChannelId: "not-an-authority-field",
      }),
    });

    expect(result).toEqual({
      kind: "provider",
      extensionId: EXTENSION_ID,
      documentId: DOCUMENT_ID,
      origin: "https://iframe.example",
      tabId: 19,
      frameId: 4,
    });
    expect(Object.isFrozen(result)).toBe(true);
    expect(JSON.stringify(result)).not.toContain("not-an-authority-field");
  });

  it.each([
    ["wrong extension owner", { id: OTHER_EXTENSION_ID }],
    ["missing extension owner", { id: undefined }],
    ["missing document identity", { documentId: undefined }],
    ["blank document identity", { documentId: "" }],
    ["missing tab", { tab: undefined }],
    ["invalid tab id", { tab: { id: -1 } }],
    ["missing frame id", { frameId: undefined }],
    ["invalid frame id", { frameId: -1 }],
    ["opaque origin", { origin: "null", url: "about:blank" }],
    ["non-web origin", { origin: "file://", url: "file:///tmp/dapp.html" }],
    ["origin with a path", { origin: "https://dapp.example/path" }],
    ["URL/origin mismatch", { origin: "https://parent.example" }],
    ["malformed URL", { url: "not a url" }],
    ["non-active lifecycle", { documentLifecycle: "prerender" }],
    ["native application ambiguity", { nativeApplication: "host" }],
  ])("rejects %s", (_label, overrides) => {
    expect(() =>
      classifyProviderSender({
        runtimeId: EXTENSION_ID,
        sender: providerSender(overrides),
      }),
    ).toThrow(SenderProvenanceError);
  });

  it("rejects browser metadata above the explicit URL size ceiling", () => {
    expect(() =>
      classifyProviderSender({
        runtimeId: EXTENSION_ID,
        sender: providerSender({ url: `https://dapp.example/${"x".repeat(8192)}` }),
      }),
    ).toThrow(SenderProvenanceError);
  });

  it("keeps document identity in the tuple when Chrome reuses a tab and frame", () => {
    const first = classifyProviderSender({
      runtimeId: EXTENSION_ID,
      sender: providerSender({ documentId: "11111111-1111-4111-8111-111111111111" }),
    });
    const afterNavigation = classifyProviderSender({
      runtimeId: EXTENSION_ID,
      sender: providerSender({ documentId: "22222222-2222-4222-8222-222222222222" }),
    });

    expect(first.tabId).toBe(afterNavigation.tabId);
    expect(first.frameId).toBe(afterNavigation.frameId);
    expect(first.documentId).not.toBe(afterNavigation.documentId);
  });
});

describe("privileged extension UI Port.sender provenance", () => {
  it("accepts only an exact allowlisted tabless extension page", () => {
    const result = classifyPrivilegedUiSender({
      runtimeId: EXTENSION_ID,
      sender: uiSender(),
      allowedPaths: ["/popup.html"],
    });

    expect(result).toEqual({
      kind: "privileged-ui",
      extensionId: EXTENSION_ID,
      documentId: DOCUMENT_ID,
      extensionOrigin: `chrome-extension://${EXTENSION_ID}`,
      path: "/popup.html",
      tabId: null,
      frameId: null,
    });
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("accepts an allowlisted full-page UI only in the tab's top frame", () => {
    expect(
      classifyPrivilegedUiSender({
        runtimeId: EXTENSION_ID,
        sender: uiSender({
          frameId: 0,
          tab: { id: 23, url: `chrome-extension://${EXTENSION_ID}/approval.html` },
          url: `chrome-extension://${EXTENSION_ID}/approval.html`,
        }),
        allowedPaths: ["/approval.html"],
      }),
    ).toMatchObject({ path: "/approval.html", tabId: 23, frameId: 0 });
  });

  it("rejects a content script that shares the extension id but claims the UI channel", () => {
    expect(() =>
      classifyPrivilegedUiSender({
        runtimeId: EXTENSION_ID,
        sender: providerSender(),
        allowedPaths: ["/popup.html"],
      }),
    ).toThrow(SenderProvenanceError);
  });

  it.each([
    ["another extension", { id: OTHER_EXTENSION_ID }],
    ["missing document identity", { documentId: undefined }],
    ["web origin", { origin: "https://dapp.example" }],
    ["another extension origin", { origin: `chrome-extension://${OTHER_EXTENSION_ID}` }],
    ["unallowlisted path", { url: `chrome-extension://${EXTENSION_ID}/settings.html` }],
    ["query ambiguity", { url: `chrome-extension://${EXTENSION_ID}/popup.html?mode=approve` }],
    ["fragment ambiguity", { url: `chrome-extension://${EXTENSION_ID}/popup.html#approve` }],
    ["nested UI frame", { frameId: 2, tab: { id: 23 } }],
    ["frame without tab", { frameId: 0 }],
    ["tab without frame", { tab: { id: 23 } }],
    ["non-active lifecycle", { documentLifecycle: "cached" }],
    ["native application ambiguity", { nativeApplication: "host" }],
  ])("rejects %s", (_label, overrides) => {
    expect(() =>
      classifyPrivilegedUiSender({
        runtimeId: EXTENSION_ID,
        sender: uiSender(overrides),
        allowedPaths: ["/popup.html"],
      }),
    ).toThrow(SenderProvenanceError);
  });

  it.each([
    [[]],
    [["popup.html"]],
    [["/popup.html?mode=approve"]],
    [["/../popup.html"]],
    [["/%70opup.html"]],
    [["//popup.html"]],
    [["/ui//popup.html"]],
    [["/popup.html/"]],
  ])("rejects malformed or ambiguous UI allowlists: %j", (allowedPaths) => {
    expect(() =>
      classifyPrivilegedUiSender({
        runtimeId: EXTENSION_ID,
        sender: uiSender(),
        allowedPaths,
      }),
    ).toThrow(SenderProvenanceError);
  });
});
