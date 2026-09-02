/*! Self-contained yaml@2.8.1 parser bundle entry. yaml is ISC licensed. */
import { isAlias, isScalar, LineCounter, parseDocument, visit } from "yaml";

export const YAML_BUNDLE_VERSION = "yaml@2.8.1";

export function parseYamlReferenceRecords(text, file) {
  const lineCounter = new LineCounter();
  const document = parseDocument(text, {
    lineCounter,
    prettyErrors: false,
    strict: true,
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    const error = document.errors[0];
    const line = error.linePos?.[0]?.line ?? 1;
    throw new Error(`${file}:${line}: invalid YAML: ${error.message}`);
  }
  const records = [];
  visit(document, {
    Pair(_key, pair) {
      const key = isScalar(pair.key) && typeof pair.key.value === "string"
        ? pair.key.value
        : null;
      if (key !== "uses" && key !== "image") return;

      let value = null;
      if (isScalar(pair.value) && typeof pair.value.value === "string") {
        value = pair.value.value;
      } else if (isAlias(pair.value)) {
        const resolved = pair.value.resolve(document);
        if (isScalar(resolved) && typeof resolved.value === "string") {
          value = resolved.value;
        }
      }
      const offset = pair.key?.range?.[0] ?? pair.value?.range?.[0] ?? 0;
      records.push({ line: lineCounter.linePos(offset).line, key, value });
    },
  });
  return records;
}
