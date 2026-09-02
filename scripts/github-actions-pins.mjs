import { readdir, readFile } from "node:fs/promises";
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

export async function auditGitHubActionReferences(
  root = process.cwd(),
  workflowsDirectory = path.join(root, ".github", "workflows"),
) {
  const files = await workflowFiles(workflowsDirectory);
  const externalReferences = [];
  const mutableReferences = [];

  for (const file of files) {
    const relativeFile = path.relative(root, file);
    const lines = (await readFile(file, "utf8")).split(/\r?\n/);
    for (const [index, line] of lines.entries()) {
      const value = parseUsesValue(line);
      if (value === null || value.startsWith("./")) continue;
      externalReferences.push(value);
      if (!isImmutableExternalReference(value)) {
        mutableReferences.push(`${relativeFile}:${index + 1}: ${value}`);
      }
    }
  }

  return { files, externalReferences, mutableReferences };
}
