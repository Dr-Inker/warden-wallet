import { describe, it, expect } from "vitest";
import { FEE_BPS, MAX_TX_BYTES, STAGE_CHUNK_PAYLOAD_CAP } from "../src/index.js";
describe("constants", () => {
  it("fee is Phantom parity", () => expect(FEE_BPS).toBe(85));
  it("tx limit is 1232", () => expect(MAX_TX_BYTES).toBe(1232));
  it("stage chunk cap is the v0 client contract 977", () => expect(STAGE_CHUNK_PAYLOAD_CAP).toBe(977));
});
