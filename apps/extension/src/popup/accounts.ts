import { isAccountAddress, isAccountLabel, MAX_SAVED_ACCOUNTS, type AccountCommand, type AccountRegistry } from "../account-registry-protocol.js";
import { requestAccounts, type AccountClientRuntime } from "./account-client.js";

export function initializeAccounts(): void {
  const root = document.querySelector<HTMLElement>("#saved-accounts");
  if (root === null) return;
  function element<T extends HTMLElement>(id: string): T {
    const found = document.getElementById(id);
    if (found === null) throw new Error(`Missing account control: ${id}`);
    return found as T;
  }
  const status = element<HTMLElement>("accounts-status");
  const welcome = element<HTMLElement>("accounts-welcome");
  const home = element<HTMLElement>("accounts-home");
  const form = element<HTMLFormElement>("account-form");
  const label = element<HTMLInputElement>("account-label");
  const address = element<HTMLTextAreaElement>("account-input");
  const select = element<HTMLSelectElement>("account-select");
  const selectedAddress = element<HTMLElement>("account-address");
  const add = element<HTMLButtonElement>("account-add");
  const cancel = element<HTMLButtonElement>("account-cancel");
  const reload = element<HTMLButtonElement>("accounts-reload");
  const remove = element<HTMLButtonElement>("account-remove");
  const removal = element<HTMLElement>("account-removal");
  const confirmRemove = element<HTMLButtonElement>("account-remove-confirm");
  const cancelRemove = element<HTMLButtonElement>("account-remove-cancel");
  const controller = new AbortController();
  let registry: AccountRegistry | undefined;
  let busy = false;
  let removing: string | null = null;
  let closed = false;

  const showHome = (): void => {
    form.hidden = true;
    removal.hidden = true;
    removing = null;
    welcome.hidden = registry === undefined || registry.accounts.length > 0;
    home.hidden = registry === undefined || registry.accounts.length === 0;
    add.hidden = registry === undefined || registry.accounts.length >= MAX_SAVED_ACCOUNTS;
  };

  const render = (): void => {
    select.replaceChildren();
    if (registry !== undefined) {
      for (const account of registry.accounts) {
        const option = document.createElement("option");
        option.value = account.address;
        option.textContent = `${account.label} · ${account.address.slice(0, 4)}…${account.address.slice(-4)}`;
        select.append(option);
      }
      select.value = registry.selectedAddress ?? "";
      selectedAddress.textContent = registry.selectedAddress;
    }
    showHome();
  };

  const run = async (command: AccountCommand): Promise<void> => {
    if (busy || closed) return;
    busy = true;
    root.setAttribute("aria-busy", "true");
    for (const control of root.querySelectorAll<HTMLInputElement | HTMLButtonElement | HTMLSelectElement | HTMLTextAreaElement>("input, button, select, textarea")) control.disabled = true;
    status.textContent = command.method === "accounts:list" ? "Loading saved accounts…" : "Saving changes…";
    status.dataset.state = "loading";
    let focusAfter: HTMLElement | undefined;
    try {
      const runtime = (globalThis as { chrome?: { runtime?: AccountClientRuntime } }).chrome?.runtime;
      if (runtime === undefined) throw new Error("Extension unavailable");
      const result = await requestAccounts(runtime, command, controller.signal);
      if (closed) return;
      registry = result;
      status.dataset.state = "ready";
      status.textContent = command.method === "accounts:list" ? "Saved on this device only." : "Changes saved on this device.";
      render();
      if (command.method !== "accounts:list") {
        focusAfter = registry.accounts.length > 0 ? select : add;
      }
    } catch {
      if (closed) return;
      registry = undefined;
      render();
      status.dataset.state = "error";
      status.textContent = "Saved accounts could not be confirmed. Reload accounts before trying again.";
    } finally {
      busy = false;
      root.setAttribute("aria-busy", "false");
      for (const control of root.querySelectorAll<HTMLInputElement | HTMLButtonElement | HTMLSelectElement | HTMLTextAreaElement>("input, button, select, textarea")) control.disabled = false;
      reload.hidden = registry !== undefined;
      if (!closed) focusAfter?.focus();
    }
  };

  add.addEventListener("click", () => {
    if (busy || registry === undefined) return;
    welcome.hidden = true;
    home.hidden = true;
    add.hidden = true;
    form.hidden = false;
    label.value = `Account ${registry.accounts.length + 1}`;
    address.value = "";
    label.focus();
  });
  cancel.addEventListener("click", () => {
    if (!busy) {
      render();
      status.textContent = "Saved on this device only.";
      add.focus();
    }
  });
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy || registry === undefined) return;
    const account = { address: address.value.trim(), label: label.value.trim() };
    if (!isAccountLabel(account.label)) {
      status.textContent = "Enter a name of 1–40 characters without control characters.";
      label.focus();
      return;
    }
    if (!isAccountAddress(account.address)) {
      status.textContent = "Enter a valid Solana public address (32–44 characters).";
      address.focus();
      return;
    }
    if (registry.accounts.some((saved) => saved.address === account.address)) {
      status.textContent = "This address is already saved. Cancel to select it from your accounts.";
      address.focus();
      return;
    }
    void run({ method: "accounts:add", params: account });
  });
  select.addEventListener("change", () => {
    if (!busy && registry !== undefined) void run({ method: "accounts:select", params: { address: select.value } });
  });
  reload.addEventListener("click", () => { void run({ method: "accounts:list", params: {} }); });
  remove.addEventListener("click", () => {
    if (busy || registry?.selectedAddress == null) return;
    removing = registry.selectedAddress;
    removal.hidden = false;
    confirmRemove.focus();
  });
  cancelRemove.addEventListener("click", () => {
    removing = null;
    removal.hidden = true;
    remove.focus();
  });
  confirmRemove.addEventListener("click", () => {
    if (removing !== null) void run({ method: "accounts:remove", params: { address: removing } });
  });
  globalThis.addEventListener("pagehide", () => { closed = true; controller.abort(); }, { once: true });
  showHome();
  void run({ method: "accounts:list", params: {} });
}
