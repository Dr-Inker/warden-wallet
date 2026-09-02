import { lstat, readdir, readFile, realpath } from "node:fs/promises";
import path from "node:path";

import { parseYamlReferenceRecords } from "./vendor/yaml-parser.mjs";

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
    const records = parseYamlReferenceRecords(
      await readFile(canonicalFile, "utf8"),
      relativeFile,
    );
    for (const { line, key, value } of records) {
      if (key === "image") {
        if (value === null) {
          mutableReferences.push(`${relativeFile}:${line}: non-literal image value`);
          continue;
        }
        if (value.startsWith("docker://")) {
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
