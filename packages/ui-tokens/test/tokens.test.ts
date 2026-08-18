import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../tokens.css", import.meta.url), "utf8");
const json: Record<string, string> = JSON.parse(
  readFileSync(new URL("../tokens.json", import.meta.url), "utf8"),
);

/** Pull the declarations of one CSS block into a name -> value map. */
function block(pattern: RegExp): Record<string, string> {
  const m = css.match(pattern);
  if (!m || m[1] === undefined) throw new Error(`block not found: ${pattern}`);
  const out: Record<string, string> = {};
  for (const decl of m[1].split(";")) {
    const i = decl.indexOf(":");
    if (i < 0) continue;
    const name = decl.slice(0, i).trim();
    if (!name.startsWith("--w-")) continue;
    out[name] = decl.slice(i + 1).trim();
  }
  return out;
}

// `:root{` only — never `:root[data-theme…]` or `:root:not(…)`.
const root = block(/:root\{([^}]*)\}/);
const darkMedia = block(/:root:not\(\[data-theme="light"\]\)\{([^}]*)\}/);
const darkAttr = block(/:root\[data-theme="dark"\]\{([^}]*)\}/);

const REQUIRED = [
  "--w-bg", "--w-surface", "--w-ink", "--w-muted", "--w-hairline",
  "--w-accent", "--w-ok", "--w-warn", "--w-critical",
  "--w-radius-card", "--w-font-ui", "--w-font-mono",
  "--w-s-4", "--w-s-8", "--w-s-12", "--w-s-16", "--w-s-24", "--w-s-32", "--w-s-48",
];

/** oklch(L% C H[ / A]) -> {l, c, h}; throws if the value is not an oklch colour. */
function oklch(value: string): { l: number; c: number; h: number } {
  const m = value.match(/^oklch\(\s*([\d.]+)%\s+([\d.]+)\s+([\d.]+)/);
  if (!m) throw new Error(`not an oklch colour: ${value}`);
  return { l: Number(m[1]), c: Number(m[2]), h: Number(m[3]) };
}

describe("tokens.css :root", () => {
  it("contains exactly the required token set", () => {
    expect(Object.keys(root).sort()).toEqual([...REQUIRED].sort());
  });
});

describe("tokens.json", () => {
  it("has exactly the same names as :root", () => {
    expect(Object.keys(json).sort()).toEqual(Object.keys(root).sort());
  });

  it("has the same values as :root", () => {
    for (const name of REQUIRED) expect(json[name]).toBe(root[name]);
  });
});

describe("dark blocks", () => {
  it("only redefine names that exist in :root", () => {
    for (const name of [...Object.keys(darkMedia), ...Object.keys(darkAttr)]) {
      expect(Object.keys(root)).toContain(name);
    }
  });

  it("are identical to each other", () => {
    expect(darkAttr).toEqual(darkMedia);
  });

  it("are non-empty (a dark theme actually exists)", () => {
    expect(Object.keys(darkMedia).length).toBeGreaterThan(0);
  });
});

describe("palette constraints", () => {
  it("accent is L=50% in light and L=62% in dark", () => {
    expect(oklch(root["--w-accent"]!).l).toBe(50);
    expect(oklch(darkMedia["--w-accent"]!).l).toBe(62);
  });

  it("accent keeps one hue family across modes", () => {
    expect(oklch(darkMedia["--w-accent"]!).h).toBe(oklch(root["--w-accent"]!).h);
  });

  it("no non-semantic colour token carries chroma above 0.04", () => {
    const accentHue = oklch(root["--w-accent"]!).h;
    expect(accentHue).toBeGreaterThan(0);
    for (const name of ["--w-bg", "--w-surface", "--w-ink", "--w-muted", "--w-hairline"]) {
      for (const scope of [root, darkMedia]) {
        const value = scope[name];
        if (value === undefined) continue;
        expect(oklch(value).c).toBeLessThanOrEqual(0.04);
      }
    }
  });

  it("only the accent exceeds chroma 0.10 outside the ok/warn/critical semantics", () => {
    const loud = Object.entries(root)
      .filter(([, v]) => /^oklch\(/.test(v))
      .filter(([, v]) => oklch(v).c > 0.1)
      .map(([k]) => k)
      .sort();
    expect(loud).toEqual(["--w-accent", "--w-critical", "--w-ok", "--w-warn"]);
  });

  it("card radius is the deliberate asymmetry", () => {
    expect(root["--w-radius-card"]).toBe("12px 12px 4px 12px");
  });
});
