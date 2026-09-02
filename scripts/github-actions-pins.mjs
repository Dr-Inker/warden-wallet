import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";

export const IMMUTABLE_ACTION = /^[^/@\s]+\/[^/@\s]+(?:\/[^@\s]+)*@[0-9a-f]{40}$/;
export const IMMUTABLE_DOCKER_ACTION = /^docker:\/\/[^\s@]+@sha256:[0-9a-f]{64}$/;

export async function workflowFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const candidate = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...await workflowFiles(candidate));
    } else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
      files.push(candidate);
    }
  }

  return files;
}

export function parseUsesValue(line) {
  const match = line.match(/^\s*(?:-\s*)?uses:\s*(.*?)\s*(?:#.*)?$/);
  if (!match) return null;

  const value = match[1];
  if (
    value.length >= 2
    && ((value.startsWith("\"") && value.endsWith("\""))
      || (value.startsWith("'") && value.endsWith("'")))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

export function isImmutableExternalReference(value) {
  return IMMUTABLE_ACTION.test(value) || IMMUTABLE_DOCKER_ACTION.test(value);
}

function isWithin(parent, candidate) {
  const rel = path.relative(parent, candidate);
  return rel === "" || (!rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel));
}

function stripYamlComment(line) {
  let quote = null;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote === "\"") {
      if (character === "\\") {
        index += 1;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (quote === "'") {
      if (character === "'" && line[index + 1] === "'") {
        index += 1;
      } else if (character === quote) {
        quote = null;
      }
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
    } else if (character === "#" && (index === 0 || /\s/.test(line[index - 1]))) {
      return line.slice(0, index);
    }
  }
  if (quote !== null) throw new Error("unterminated quoted YAML scalar");
  return line;
}

function readQuotedYamlScalar(source, start) {
  const quote = source[start];
  let end = start + 1;
  while (end < source.length) {
    if (quote === "\"" && source[end] === "\\") {
      end += 2;
      continue;
    }
    if (quote === "'" && source[end] === "'" && source[end + 1] === "'") {
      end += 2;
      continue;
    }
    if (source[end] === quote) break;
    end += 1;
  }
  if (end >= source.length) throw new Error("unterminated quoted YAML scalar");
  const token = source.slice(start, end + 1);
  let value;
  if (quote === "\"") {
    try {
      value = JSON.parse(token);
    } catch {
      throw new Error("unsupported escape in double-quoted YAML scalar");
    }
  } else {
    value = token.slice(1, -1).replaceAll("''", "'");
  }
  return { value, end: end + 1 };
}

function readMappingPair(source, start) {
  let cursor = start;
  while (cursor < source.length && /[ \t]/.test(source[cursor])) cursor += 1;
  if (source[cursor] === "-" && /[ \t]/.test(source[cursor + 1] ?? "")) {
    cursor += 1;
    while (cursor < source.length && /[ \t]/.test(source[cursor])) cursor += 1;
  }

  let key;
  if (source[cursor] === "\"" || source[cursor] === "'") {
    const quoted = readQuotedYamlScalar(source, cursor);
    key = quoted.value;
    cursor = quoted.end;
  } else {
    const match = /^[A-Za-z_][A-Za-z0-9_-]*/.exec(source.slice(cursor));
    if (match === null) return null;
    key = match[0];
    cursor += match[0].length;
  }
  while (cursor < source.length && /[ \t]/.test(source[cursor])) cursor += 1;
  if (source[cursor] !== ":") return null;
  cursor += 1;
  while (cursor < source.length && /[ \t]/.test(source[cursor])) cursor += 1;

  const valueStart = cursor;
  let value;
  let blockScalar = false;
  if (source[cursor] === "\"" || source[cursor] === "'") {
    const quoted = readQuotedYamlScalar(source, cursor);
    value = quoted.value;
    const trailing = source.slice(quoted.end).trimStart();
    if (trailing !== "" && !/^[,}\]]/.test(trailing)) {
      throw new Error("unsupported content after quoted YAML scalar");
    }
  } else {
    let end = cursor;
    while (end < source.length && !/[,}\]]/.test(source[end])) end += 1;
    const raw = source.slice(cursor, end).trim();
    blockScalar = /^(?:[|>](?:[1-9][+-]?|[+-][1-9]?)?)$/.test(raw);
    value = raw !== "" && !/^[&*!|>{[]/.test(raw) ? raw : null;
  }
  return { key, value, valueStart, blockScalar };
}

function mappingPairsFromLine(line) {
  const pairs = [];
  const seen = new Set();
  const addPair = (start) => {
    if (seen.has(start)) return;
    seen.add(start);
    const pair = readMappingPair(line, start);
    if (pair !== null) pairs.push(pair);
  };

  addPair(0);
  const first = readMappingPair(line, 0);
  const mayContainFlowMapping = first === null
    ? /^[ \t]*(?:-[ \t]*)?[{[]/.test(line)
    : /^[{[]/.test(line.slice(first.valueStart));
  if (!mayContainFlowMapping) return pairs;

  let quote = null;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote === "\"") {
      if (character === "\\") index += 1;
      else if (character === quote) quote = null;
      continue;
    }
    if (quote === "'") {
      if (character === "'" && line[index + 1] === "'") index += 1;
      else if (character === quote) quote = null;
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
    } else if (character === "{" || character === "[" || character === ",") {
      addPair(index + 1);
    }
  }
  return pairs;
}

function referenceRecordsFromDocument(text, file) {
  const records = [];
  let blockScalarIndent = null;
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    if (/^[ ]*\t/.test(rawLine)) {
      throw new Error(`${file}:${index + 1}: tabs are not permitted in YAML indentation`);
    }
    const indent = rawLine.match(/^ */)[0].length;
    if (blockScalarIndent !== null) {
      if (rawLine.trim() === "" || indent > blockScalarIndent) continue;
      blockScalarIndent = null;
    }

    let line;
    try {
      line = stripYamlComment(rawLine);
    } catch (error) {
      throw new Error(`${file}:${index + 1}: ${error.message}`);
    }
    const structural = line.trimStart().replace(/^-[ \t]+/, "");
    if (/^(?:\?|!|&|\*|\[)/.test(structural) || /[{,][ \t]*(?:\?|!|&|\*)/.test(line)) {
      throw new Error(
        `${file}:${index + 1}: complex or tagged YAML mapping keys are not permitted in Actions sources`,
      );
    }
    let pairs;
    try {
      pairs = mappingPairsFromLine(line);
    } catch (error) {
      throw new Error(`${file}:${index + 1}: ${error.message}`);
    }
    const first = pairs[0];
    if (first?.blockScalar === true) {
      blockScalarIndent = indent;
    }
    for (const pair of pairs) {
      if (pair.key === "uses" || pair.key === "image") {
        records.push({ line: index + 1, key: pair.key, value: pair.value });
      }
    }
  }
  return records;
}

async function resolveLocalDefinition(canonicalRoot, value) {
  if (
    typeof value !== "string"
    || !value.startsWith("./")
    || value.includes("\0")
    || value.includes("\\")
  ) {
    throw new Error(`invalid local action reference: ${String(value)}`);
  }
  const candidate = path.resolve(canonicalRoot, value);
  if (!isWithin(canonicalRoot, candidate)) {
    throw new Error(`local action reference escapes the repository: ${value}`);
  }
  const candidateMetadata = await lstat(candidate);
  if (candidateMetadata.isSymbolicLink()) {
    throw new Error(`local action reference must not be a symlink: ${value}`);
  }
  if (candidateMetadata.isFile()) {
    if (!/\.ya?ml$/i.test(candidate)) {
      throw new Error(`local reusable workflow must be YAML: ${value}`);
    }
    return await realpath(candidate);
  }
  if (!candidateMetadata.isDirectory()) {
    throw new Error(`local action reference is not a file or directory: ${value}`);
  }
  const definitions = [];
  for (const name of ["action.yml", "action.yaml"]) {
    const definition = path.join(candidate, name);
    try {
      const metadata = await lstat(definition);
      if (!metadata.isFile() || metadata.isSymbolicLink()) {
        throw new Error(`local action definition must be a regular file: ${value}/${name}`);
      }
      definitions.push(await realpath(definition));
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
  }
  if (definitions.length !== 1) {
    throw new Error(`local action must contain exactly one action.yml or action.yaml: ${value}`);
  }
  return definitions[0];
}

export async function auditGitHubActionReferences(
  root = process.cwd(),
  workflowsDirectory = path.join(root, ".github", "workflows"),
) {
  const canonicalRoot = await realpath(root);
  const entryFiles = await workflowFiles(workflowsDirectory);
  const files = [];
  const externalReferences = [];
  const mutableReferences = [];

  const visited = new Set();
  const scan = async (file) => {
    const canonicalFile = await realpath(file);
    if (!isWithin(canonicalRoot, canonicalFile)) {
      throw new Error(`GitHub Actions source escapes the repository: ${file}`);
    }
    if (visited.has(canonicalFile)) return;
    visited.add(canonicalFile);
    files.push(canonicalFile);
    const relativeFile = path.relative(canonicalRoot, canonicalFile);
    const records = referenceRecordsFromDocument(
      await readFile(canonicalFile, "utf8"),
      relativeFile,
    );
    for (const { line, key, value } of records) {
      if (key === "image") {
        if (typeof value === "string" && value.startsWith("docker://")) {
          externalReferences.push(value);
          if (!isImmutableExternalReference(value)) {
            mutableReferences.push(`${relativeFile}:${line}: ${value}`);
          }
        }
        continue;
      }
      if (value === null) {
        mutableReferences.push(`${relativeFile}:${line}: non-literal uses value`);
        continue;
      }
      if (value.startsWith("./")) {
        await scan(await resolveLocalDefinition(canonicalRoot, value));
        continue;
      }
      externalReferences.push(value);
      if (!isImmutableExternalReference(value)) {
        mutableReferences.push(`${relativeFile}:${line}: ${value}`);
      }
    }
  };
  for (const file of entryFiles) await scan(file);

  return { files, externalReferences, mutableReferences };
}
