// scripts/proveGuardian.ts
import fs from "fs/promises";
import path from "path";
import zk   from "@zk-email/sdk";
import * as dotenv from "dotenv";
dotenv.config();

/* ───────── config ───────── */
const BLUEPRINT = "zkemail/guardian_accept@v1"; // public slug
const EMAIL_DIR = "./emails";
const OUT_DIR   = "./script/proofs";
const WALLET    = "0x5615dEb798bb3e4Dfa0139dFa1B3D433cC23b72f".toLowerCase();

/* salts map you already created */
const SALTS = JSON.parse(await fs.readFile(
  "script/data/guardians_salt.json", "utf8"
));

/* make sure output dir exists */
await fs.mkdir(OUT_DIR, { recursive: true });

/* 1️⃣  SDK with your API key */
const sdk       = new zk.ZkEmailSDK({ apiKey: process.env.ZKE_API_KEY });
const blueprint = await sdk.getBlueprint(BLUEPRINT);         // remote fetch
const prover    = blueprint.createProver();                  // cloud Groth16

/* 2️⃣  prove every .eml in emails/ */
for (const f of (await fs.readdir(EMAIL_DIR)).filter(x=>x.endsWith(".eml"))) {
  const raw   = await fs.readFile(path.join(EMAIL_DIR,f), "utf8");

  /* grab sender address from file name or From: header (quick regex) */
  const sender = /From:.*<([^>]+)>/i.exec(raw)?.[1]?.toLowerCase() ?? "";
  if (!sender) { console.warn("skip (no From):",f); continue; }

  const salt = SALTS[sender];
  if (!salt) { console.warn("skip (no salt):",sender); continue; }

  console.log("⏳ proving →", sender);

  const proofPkg = await prover.generateProof(
    raw,
    [
      { name: "ethAddr",     value: WALLET, maxLength: 20 },
      { name: "accountSalt", value: salt,   maxLength: 32 }
    ]
  );

  const out = path.join(OUT_DIR, `${proofPkg.emailAuth}.json`);
  await fs.writeFile(out, JSON.stringify(proofPkg, null, 2));
  console.log("✅ saved:", out);
}