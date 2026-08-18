import { Connection, PublicKey, VersionedTransaction, Keypair } from "@solana/web3.js";
import { wrapForExecute } from "./wrap.js";
const RPC = process.env.RPC ?? "https://api.mainnet-beta.solana.com";
const conn = new Connection(RPC);
const user = new PublicKey("11111111111111111111111111111112"); // any funded pubkey works for quotes; swap tx build needs a real owner: use env USER_PUBKEY
const owner = new PublicKey(process.env.USER_PUBKEY ?? user.toBase58());
let lastJupiterHops: number | undefined;
async function jupiter(): Promise<VersionedTransaction> {
  // NOTE: the brief's original URL included platformFeeBps=85, but Jupiter's /swap rejects that
  // without a feeAccount in the POST body ("feeAccount is required for swap with platformFee").
  // Dropped platformFeeBps since a spike doesn't need real fee revenue, just a realistic route.
  const q = await (await fetch(`https://lite-api.jup.ag/swap/v1/quote?inputMint=So11111111111111111111111111111111111111112&outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=100000000&slippageBps=50`)).json();
  lastJupiterHops = Array.isArray(q.routePlan) ? q.routePlan.length : undefined; // hop count for result.md
  const s = await (await fetch("https://lite-api.jup.ag/swap/v1/swap", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ quoteResponse: q, userPublicKey: owner.toBase58(), wrapAndUnwrapSol: true }) })).json();
  if (!s.swapTransaction) throw new Error(`jupiter swap build failed: ${JSON.stringify(s)}`);
  return VersionedTransaction.deserialize(Buffer.from(s.swapTransaction, "base64"));
}

// --- Tensor: @tensor-oss/tensorswap-sdk builds instructions from on-chain pool/listing accounts
// you must already know (mint, pool, owner) — it has no "give me any current listing" helper, so
// exercising it still requires Tensor's REST API first to discover a live listing. Went straight
// to the REST API (their documented path for buy-tx construction) and hit the auth wall below. ---
async function tensor(): Promise<VersionedTransaction> {
  // Tensor's on-chain buy-now tx requires a specific listed NFT mint known at request time; there
  // is no "any NFT" quote endpoint like Jupiter's. We'd resolve a currently-listed NFT via
  // Tensor's public REST API, then build the buy tx through the same API — but the API requires
  // an API key for every endpoint we tried (no anonymous tier), confirmed by the probe below.
  const apiKey = process.env.TENSOR_API_KEY;
  const res = await fetch("https://api.mainnet.tensordev.io/api/v1/mint/collection_stats?slug=mad_lads", apiKey ? { headers: { "x-tensor-api-key": apiKey } } : {});
  const body = await res.text();
  if (!res.ok) throw new Error(`not measured — Tensor REST API rejected the request without TENSOR_API_KEY: HTTP ${res.status} "${body}" (no key available in this environment; unlike Jupiter, Tensor has no anonymous tier and there is no "any listing" quote endpoint — a buy-now tx also needs a specific listed NFT mint resolved via an authed /listings call first)`);
  throw new Error("not measured — got past auth probe unexpectedly; buy-tx flow still not implemented, see result.md");
}

// --- Marinade: attempted via @marinade.finance/marinade-ts-sdk deposit() builder. ---
async function marinade(): Promise<VersionedTransaction> {
  let Marinade: any, MarinadeConfig: any;
  try {
    ({ Marinade, MarinadeConfig } = await import("@marinade.finance/marinade-ts-sdk"));
  } catch (e: any) {
    throw new Error(`not measured — @marinade.finance/marinade-ts-sdk not installed/buildable: ${e?.message ?? e}`);
  }
  const { default: BN } = await import("bn.js");
  const config = new MarinadeConfig({ connection: conn, publicKey: owner });
  const marinade = new Marinade(config);
  const { transaction } = await marinade.deposit(new BN(1_000_000_000)); // deposit() wants BN, not bigint
  // Marinade SDK returns a legacy Transaction; convert to a VersionedTransaction (v0, no LUTs) for
  // apples-to-apples measurement against wrapForExecute (which expects VersionedMessage).
  const { TransactionMessage } = await import("@solana/web3.js");
  const { blockhash } = await conn.getLatestBlockhash();
  const msg = new TransactionMessage({
    payerKey: owner,
    recentBlockhash: blockhash,
    instructions: transaction.instructions,
  }).compileToV0Message();
  return new VersionedTransaction(msg);
}

async function main() {
  const cases: Record<string, () => Promise<VersionedTransaction>> = {
    "jupiter SOL→USDC 0.1": jupiter,
    "tensor buy-now (attempt)": tensor,
    "marinade deposit 1 SOL (attempt)": marinade,
  };
  const wardenProgram = Keypair.generate().publicKey, account = owner, session = Keypair.generate().publicKey;
  for (const [name, build] of Object.entries(cases)) {
    try {
      const tx = await build();
      const luts = await Promise.all(tx.message.addressTableLookups.map(async l => (await conn.getAddressLookupTable(l.accountKey)).value!));
      const r = wrapForExecute(tx.message, wardenProgram, account, session, luts);
      const hops = name.startsWith("jupiter") ? lastJupiterHops : undefined;
      // Three honest, distinct metrics over the ORIGINAL (pre-wrap) message (round 5 review —
      // Important; the old single `writableAccounts` field actually counted every key regardless
      // of writability, and wasn't the wrapped `execute` instruction's own account count either):
      //   - totalKeys: every original-message key — static account keys plus every LUT index
      //     (writable + readonly). This is exactly what the old `writableAccounts` field computed
      //     despite its name — kept as `totalKeys` now that it's honestly labeled.
      //   - writableKeys: payer + writable static accounts (derived from the message header's
      //     numRequiredSignatures/numReadonlySignedAccounts/numReadonlyUnsignedAccounts split) plus
      //     writable LUT indexes only.
      //   - executeAccountCount: the length of the WRAPPED `execute` instruction's own account
      //     list (`outerKeys`, from `wrapForExecute`'s return value) — a different message
      //     entirely (the outer/wrapped one, not the original dApp-built one).
      const header = tx.message.header;
      const numStatic = tx.message.staticAccountKeys.length;
      const writableSignedStatics = header.numRequiredSignatures - header.numReadonlySignedAccounts;
      const writableUnsignedStatics = (numStatic - header.numRequiredSignatures) - header.numReadonlyUnsignedAccounts;
      const writableLutKeys = tx.message.addressTableLookups.reduce((a, l) => a + l.writableIndexes.length, 0);
      const totalKeys = numStatic + tx.message.addressTableLookups.reduce((a, l) => a + l.writableIndexes.length + l.readonlyIndexes.length, 0);
      const writableKeys = writableSignedStatics + writableUnsignedStatics + writableLutKeys;
      console.log(JSON.stringify({ name, bytesOriginal: r.bytesOriginal, bytesInline: r.bytesInline, fitsInline: !!r.inline, stagedChunks: r.stagedChunks, totalKeys, writableKeys, executeAccountCount: r.executeAccountCount, ...(hops !== undefined ? { hops } : {}) }));
    } catch (e: any) {
      console.log(JSON.stringify({ name, error: String(e?.message ?? e) }));
    }
  }
}
main().catch(e => { console.error(e); process.exit(1); });
