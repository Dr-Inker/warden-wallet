import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
const css = readFileSync(new URL("../tokens.css", import.meta.url), "utf8");
const json = JSON.parse(readFileSync(new URL("../tokens.json", import.meta.url), "utf8"));
describe("tokens", () => {
  it("every json token exists in css :root", () => { for (const name of Object.keys(json)) expect(css.includes(`${name}:`)).toBe(true); });
  it("dark block redefines only tokens defined in :root", () => {
    const root = css.split("@media")[0]; const dark = css.split("@media")[1] ?? "";
    for (const m of dark.matchAll(/(--w-[a-z0-9-]+):/g)) expect(root.includes(`${m[1]}:`)).toBe(true);
  });
  it("exactly one accent hue family", () => expect((css.match(/--w-accent:/g) ?? []).length).toBe(3));
});
