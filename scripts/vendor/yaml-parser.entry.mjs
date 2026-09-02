/*! Self-contained yaml@2.8.1 parser bundle entry. yaml is ISC licensed. */
import { isAlias, isScalar, LineCounter, parseDocument, visit } from "yaml";

export const YAML_BUNDLE_VERSION = "yaml@2.8.1";

function resolvedString(node, document) {
  if (isScalar(node) && typeof node.value === "string") return node.value;
  if (!isAlias(node)) return null;
  const resolved = node.resolve(document);
  return isScalar(resolved) && typeof resolved.value === "string"
    ? resolved.value
    : null;
}

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
      const key = resolvedString(pair.key, document);
      const offset = pair.key?.range?.[0] ?? pair.value?.range?.[0] ?? 0;
      if (isAlias(pair.key) && key === null) {
        throw new Error(
          `${file}:${lineCounter.linePos(offset).line}: non-literal YAML mapping key is not permitted`,
        );
      }
      if (key !== "uses" && key !== "image") return;

      const value = resolvedString(pair.value, document);
      records.push({ line: lineCounter.linePos(offset).line, key, value });
    },
  });
  return records;
}
