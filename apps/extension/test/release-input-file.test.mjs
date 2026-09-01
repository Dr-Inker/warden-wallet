import {
  mkdir,
  mkdtemp,
  open,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { readBoundedRegularFile } from "../scripts/release-input-file.mjs";

const temporaryDirectories = [];
const FILE_BYTES = 16 * 1024 * 1024;
const MUTATION_BURST = 64;

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("stable bounded release input files", () => {
  it("rejects a symlink in a parent path component", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-input-file-test-"));
    temporaryDirectories.push(directory);
    const actualDirectory = join(directory, "actual");
    const linkedDirectory = join(directory, "linked");
    await mkdir(actualDirectory);
    await writeFile(join(actualDirectory, "candidate.bin"), "candidate bytes\n");
    await symlink(actualDirectory, linkedDirectory, "dir");

    let rejection;
    try {
      await readBoundedRegularFile(
        join(linkedDirectory, "candidate.bin"),
        1024,
        "parent symlink candidate",
      );
    } catch (error) {
      rejection = error;
    }
    expect(rejection).toBeInstanceOf(Error);
    expect(rejection?.message).toMatch(
      /opened path differs from the normalized requested path/,
    );
  });

  it("rejects same-size in-place mutation during a stable-handle read", async () => {
    const directory = await mkdtemp(join(tmpdir(), "warden-release-input-file-test-"));
    temporaryDirectories.push(directory);
    const candidatePath = join(directory, "candidate.bin");
    await writeFile(candidatePath, Buffer.from([0]));
    await truncate(candidatePath, FILE_BYTES);

    const writer = await open(candidatePath, "r+");
    let mutationCount = 0;
    let stopped = false;
    const mutations = (async () => {
      while (!stopped && mutationCount < MUTATION_BURST) {
        const byte = Buffer.from([(mutationCount % 251) + 1]);
        await writer.write(byte, 0, byte.length, 0);
        mutationCount += 1;
        await new Promise((resolve) => setImmediate(resolve));
      }
    })();

    let rejection;
    try {
      await readBoundedRegularFile(candidatePath, FILE_BYTES, "mutation candidate");
    } catch (error) {
      rejection = error;
    } finally {
      stopped = true;
      await mutations;
      await writer.close();
    }
    expect(rejection).toBeInstanceOf(Error);
    expect(rejection?.message).toMatch(/changed while it was being read/);
    expect(mutationCount).toBeGreaterThan(1);
  });
});
