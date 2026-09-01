import { constants as fsConstants } from "node:fs";
import { open } from "node:fs/promises";

function fail(message) {
  throw new Error(`extension release input file: ${message}`);
}

export async function readBoundedRegularFile(path, maximumBytes, label) {
  if (typeof label !== "string" || label.length === 0) {
    fail("input label is required");
  }
  if (typeof path !== "string" || path.length === 0) {
    fail(`${label} path is required`);
  }
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    fail(`${label} maximum byte count must be a positive safe integer`);
  }

  let handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  } catch (error) {
    fail(
      `${label} could not be opened as a non-symlink regular file: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.size <= 0 || before.size > maximumBytes) {
      fail(`${label} must be a nonempty regular file no larger than ${maximumBytes} bytes`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!after.isFile() || bytes.length !== before.size || after.size !== before.size) {
      fail(`${label} changed size while it was being read`);
    }
    return bytes;
  } finally {
    await handle.close();
  }
}
