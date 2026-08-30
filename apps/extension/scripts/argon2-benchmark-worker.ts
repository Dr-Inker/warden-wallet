import {
  ARGON2ID_ASYNC_TICK_MS,
  PROVISIONAL_ARGON2ID_PARAMS,
  deriveUnwrapKeyFromPasswordBytesAsync,
} from "../../../packages/core/src/keyring/derive.js";
import { KeyringLockedError } from "../../../packages/core/src/keyring/errors.js";

const SAMPLE_COUNT = 5;
const HOST_TASK_REQUEST_DELAY_MS = 50;
const EXPECTED_HEX =
  "b6f32acca042df7ef578e6bed336c0e31a1c06cbce489124cb35fe052f62d39c";
const SALT = new Uint8Array(16).fill(0x53);

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function rounded(value: number): number {
  return Number(value.toFixed(3));
}

function percentile(values: readonly number[], fraction: number): number {
  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.max(0, Math.ceil(sorted.length * fraction) - 1);
  return sorted[index]!;
}

async function benchmarkArgon2() {
  const samples: Array<{
    readonly elapsedMs: number;
    readonly hostTaskDelayMs: number;
  }> = [];

  for (let sample = 0; sample < SAMPLE_COUNT; sample++) {
    const password = new TextEncoder().encode("warden-argon2-calibration");
    let hostTaskAt: number | undefined;
    const startedAt = performance.now();
    const hostTask = new Promise<void>((resolve) => {
      setTimeout(() => {
        hostTaskAt = performance.now();
        resolve();
      }, HOST_TASK_REQUEST_DELAY_MS);
    });
    const key = await deriveUnwrapKeyFromPasswordBytesAsync(
      password,
      SALT,
      PROVISIONAL_ARGON2ID_PARAMS,
    );
    const finishedAt = performance.now();
    await hostTask;

    if (hex(key.bytes) !== EXPECTED_HEX) {
      key.bytes.fill(0);
      throw new Error("Argon2 benchmark output did not match the fixed regression vector");
    }
    if (password.some((byte) => byte !== 0)) {
      key.bytes.fill(0);
      throw new Error("Argon2 benchmark password buffer was not wiped");
    }
    if (hostTaskAt === undefined || hostTaskAt >= finishedAt) {
      key.bytes.fill(0);
      throw new Error("Argon2 benchmark did not yield to a browser host task before completion");
    }
    samples.push({
      elapsedMs: rounded(finishedAt - startedAt),
      hostTaskDelayMs: rounded(hostTaskAt - startedAt),
    });
    key.bytes.fill(0);
  }

  const elapsed = samples.map((sample) => sample.elapsedMs);
  const hostTaskDelays = samples.map((sample) => sample.hostTaskDelayMs);
  const revokedPassword = new TextEncoder().encode("warden-argon2-revocation");
  const controller = new AbortController();
  let abortDispatchedAt: number | undefined;
  const revocationStartedAt = performance.now();
  const abortTask = new Promise<void>((resolve) => {
    setTimeout(() => {
      abortDispatchedAt = performance.now();
      controller.abort();
      resolve();
    }, HOST_TASK_REQUEST_DELAY_MS);
  });
  let revocationError: unknown;
  try {
    await deriveUnwrapKeyFromPasswordBytesAsync(
      revokedPassword,
      SALT,
      PROVISIONAL_ARGON2ID_PARAMS,
      { signal: controller.signal },
    );
  } catch (error) {
    revocationError = error;
  }
  const revocationSettledAt = performance.now();
  await abortTask;
  if (!(revocationError instanceof KeyringLockedError)) {
    throw new Error("Argon2 benchmark did not reject with KeyringLockedError after revocation");
  }
  if (revokedPassword.some((byte) => byte !== 0)) {
    throw new Error("revoked Argon2 benchmark password buffer was not wiped");
  }
  if (abortDispatchedAt === undefined || abortDispatchedAt >= revocationSettledAt) {
    throw new Error("Argon2 revocation task did not run before derivation settled");
  }
  return {
    schemaVersion: 1,
    implementation: "@noble/hashes 2.4.0 pure-JS argon2idAsync",
    profile: {
      memoryKiB: PROVISIONAL_ARGON2ID_PARAMS.memoryKiB,
      timeCost: PROVISIONAL_ARGON2ID_PARAMS.timeCost,
      parallelism: PROVISIONAL_ARGON2ID_PARAMS.parallelism,
      outputBytes: 32,
      asyncTickMs: ARGON2ID_ASYNC_TICK_MS,
      status: "PROVISIONAL_UNVERIFIED_PRODUCT_FLOOR",
    },
    sampleCount: SAMPLE_COUNT,
    hostTaskRequestedDelayMs: HOST_TASK_REQUEST_DELAY_MS,
    samples,
    elapsedMs: {
      min: rounded(Math.min(...elapsed)),
      p50: rounded(percentile(elapsed, 0.5)),
      p95: rounded(percentile(elapsed, 0.95)),
      max: rounded(Math.max(...elapsed)),
    },
    hostTaskDelayMs: {
      min: rounded(Math.min(...hostTaskDelays)),
      p50: rounded(percentile(hostTaskDelays, 0.5)),
      p95: rounded(percentile(hostTaskDelays, 0.95)),
      max: rounded(Math.max(...hostTaskDelays)),
    },
    outputHex: EXPECTED_HEX,
    revocation: {
      errorName: revocationError.name,
      abortTaskDelayMs: rounded(abortDispatchedAt - revocationStartedAt),
      settleAfterAbortMs: rounded(revocationSettledAt - abortDispatchedAt),
      passwordBufferWiped: true,
    },
    browser: {
      userAgent: navigator.userAgent,
      hardwareConcurrency: navigator.hardwareConcurrency,
    },
  };
}

Object.assign(globalThis, { __wardenArgon2Benchmark: benchmarkArgon2 });
