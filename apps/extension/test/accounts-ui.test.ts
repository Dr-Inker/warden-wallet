import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { send } = vi.hoisted(() => ({ send: vi.fn() }));
vi.mock("../src/popup/account-client.js", () => ({ requestAccounts: send }));
import { initializeAccounts } from "../src/popup/accounts.js";

const ADDRESS = "FTPSf3Po3uMpD9KRxWZtaqM27t7zCR8k7oAgz22u2eEC";
const SECOND = "3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3";
const EMPTY = { version: 1, accounts: [], selectedAddress: null };
const SAVED = { version: 1, accounts: [{ address: ADDRESS, label: "Primary" }], selectedAddress: ADDRESS };

class Element {
  hidden = false;
  disabled = false;
  value = "";
  textContent: string | null = "";
  dataset: Record<string, string> = {};
  children: Element[] = [];
  events = new Map<string, (event: Event) => void>();
  focus = vi.fn();
  setAttribute = vi.fn();
  addEventListener(name: string, listener: (event: Event) => void) { this.events.set(name, listener); }
  fire(name: string) { this.events.get(name)?.(new Event(name, { cancelable: true })); }
  replaceChildren() { this.children = []; }
  append(child: Element) { this.children.push(child); }
  querySelectorAll = (): Element[] => [];
}
function harness() {
  const elements = new Map<string, Element>();
  const get = (id: string): Element => {
    if (!elements.has(id)) elements.set(id, new Element());
    return elements.get(id)!;
  };
  const root = get("saved-accounts");
  root.querySelectorAll = () => [...elements.values()].filter((element) => element !== root);
  const events = new Map<string, () => void>();
  vi.stubGlobal("document", { querySelector: () => root, getElementById: get, createElement: () => new Element() });
  vi.stubGlobal("chrome", { runtime: { connect: vi.fn() } });
  vi.stubGlobal("addEventListener", (name: string, listener: () => void) => { events.set(name, listener); });
  return { get, events };
}
async function drain() { for (let i = 0; i < 8; i++) await Promise.resolve(); }
beforeEach(() => send.mockReset());
afterEach(() => vi.unstubAllGlobals());

describe("saved-account onboarding UI", () => {
  it("takes an empty install through name/address entry to the selected account", async () => {
    const h = harness();
    send.mockResolvedValueOnce(EMPTY).mockResolvedValueOnce(SAVED);
    initializeAccounts();
    await drain();
    expect(h.get("accounts-welcome").hidden).toBe(false);
    h.get("account-add").fire("click");
    expect(h.get("account-form").hidden).toBe(false);
    h.get("account-label").value = " Primary ";
    h.get("account-input").value = ` ${ADDRESS} `;
    h.get("account-form").fire("submit");
    await drain();
    expect(send.mock.calls[1]![1]).toEqual({ method: "accounts:add", params: { address: ADDRESS, label: "Primary" } });
    expect(h.get("accounts-home").hidden).toBe(false);
    expect(h.get("account-form").hidden).toBe(true);
    expect(h.get("account-address").textContent).toBe(ADDRESS);
    expect(h.get("account-select").value).toBe(ADDRESS);
    expect(h.get("account-select").disabled).toBe(false);
    expect(h.get("account-select").focus).toHaveBeenCalled();
  });

  it("rejects invalid or duplicate addresses without sending a mutation", async () => {
    const h = harness();
    send.mockResolvedValue(SAVED);
    initializeAccounts();
    await drain();
    h.get("account-add").fire("click");
    h.get("account-input").value = "not a Solana address";
    h.get("account-form").fire("submit");
    expect(h.get("accounts-status").textContent).toContain("valid Solana public address");
    h.get("account-input").value = ADDRESS;
    h.get("account-form").fire("submit");
    expect(h.get("accounts-status").textContent).toContain("already saved");
    expect(send).toHaveBeenCalledOnce();
  });

  it("restores and switches accounts, requiring confirmation before removal", async () => {
    const h = harness();
    const accounts = [...SAVED.accounts, { address: SECOND, label: "Savings" }];
    send.mockResolvedValueOnce({ ...SAVED, accounts }).mockResolvedValueOnce({ version: 1, accounts, selectedAddress: SECOND }).mockResolvedValueOnce(SAVED);
    initializeAccounts();
    await drain();
    h.get("account-select").value = SECOND;
    h.get("account-select").fire("change");
    await drain();
    expect(h.get("account-address").textContent).toBe(SECOND);
    h.get("account-remove").fire("click");
    expect(send).toHaveBeenCalledTimes(2);
    h.get("account-remove-cancel").fire("click");
    expect(h.get("account-removal").hidden).toBe(true);
    h.get("account-remove").fire("click");
    h.get("account-remove-confirm").fire("click");
    await drain();
    expect(send.mock.calls[2]![1]).toEqual({ method: "accounts:remove", params: { address: SECOND } });
    expect(h.get("account-address").textContent).toBe(ADDRESS);
  });

  it("hides stale accounts on failure and reloads disk before permitting another write", async () => {
    const h = harness();
    send.mockResolvedValueOnce(SAVED).mockRejectedValueOnce(new Error("write ambiguous")).mockResolvedValueOnce(EMPTY);
    initializeAccounts();
    await drain();
    h.get("account-remove").fire("click");
    h.get("account-remove-confirm").fire("click");
    await drain();
    expect(h.get("accounts-home").hidden).toBe(true);
    expect(h.get("account-add").hidden).toBe(true);
    expect(h.get("accounts-reload").hidden).toBe(false);
    expect(h.get("accounts-status").textContent).toContain("Reload accounts");
    h.get("accounts-reload").fire("click");
    await drain();
    expect(h.get("accounts-welcome").hidden).toBe(false);
    expect(h.get("account-add").hidden).toBe(false);
  });

  it("prevents repeated submissions and discards responses after pagehide", async () => {
    const h = harness();
    let resolve!: (value: unknown) => void;
    send.mockResolvedValueOnce(EMPTY).mockImplementationOnce(() => new Promise((done) => { resolve = done; }));
    initializeAccounts();
    await drain();
    h.get("account-add").fire("click");
    h.get("account-input").value = ADDRESS;
    h.get("account-form").fire("submit");
    h.get("account-form").fire("submit");
    expect(send).toHaveBeenCalledTimes(2);
    h.events.get("pagehide")!();
    expect(send.mock.calls[1]![2].aborted).toBe(true);
    resolve(SAVED);
    await drain();
    expect(h.get("accounts-home").hidden).toBe(true);
  });

  it("uses text nodes for hostile-looking account labels", async () => {
    const h = harness();
    send.mockResolvedValue({ ...SAVED, accounts: [{ address: ADDRESS, label: "<img src=x onerror=alert(1)>" }] });
    initializeAccounts();
    await drain();
    expect(h.get("account-select").children[0]!.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(h.get("account-select").children[0]).not.toHaveProperty("innerHTML");
  });
});
