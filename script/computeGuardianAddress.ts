#!/usr/bin/env ts-node

import axios from "axios";
import { universalEmailRecoveryModuleAbi } from "./utils/UniversalEmailRecoveryModule";
import { GetAccountSaltResponseSchema } from "./utils/types";
import { createPublicClient, http, type Address, type Hex } from "viem";
import { baseSepolia } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { buildPoseidon } from "circomlibjs";
import { bytesToHex } from "viem";
import fs from "fs/promises";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import "dotenv/config";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

async function generateAccountCode(): Promise<Hex> {
  const poseidon = await buildPoseidon();
  const rand     = poseidon.F.random() as any as Uint8Array;
  return bytesToHex(rand.reverse()) as Hex;
}

async function computeGuardianAddress(
  account: Address,
  accountCode: Hex,
  guardianEmail: string
): Promise<{ address: string; salt: string }> {
  const rpcUrl  = process.env.SEPOLIA_RPC!;
  const relayer = process.env.RELAYER_URL!;
  const client  = createPublicClient({ transport: http(rpcUrl), chain: baseSepolia });

  const { data } = await axios.post(`${relayer}/getAccountSalt`, {
    account_code: accountCode.slice(2),
    email_addr:   guardianEmail,
  });
  const guardianSalt = GetAccountSaltResponseSchema.parse(data);
  console.log(`  ↳ salt for ${guardianEmail}:`, guardianSalt);

  const ADDR_PATH = join(__dirname, "data", "addresses.json");
  const ADDRESSES = JSON.parse(await fs.readFile(ADDR_PATH, "utf8"));
  const address   = await client.readContract({
    abi:          universalEmailRecoveryModuleAbi,
    address:      ADDRESSES.UniversalEmailRecoveryModule,
    functionName: "computeEmailAuthAddress",
    args:         [account, guardianSalt],
  });

  return { address, salt: guardianSalt };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  (async () => {
    try {
      const owner   = privateKeyToAccount(process.env.OWNER_PRIVATE_KEY as Hex);
      const account = owner.address;
      console.log("Owner address:", account);

      const EMAILS_PATH = join(__dirname, "data", "emails.json");
      const emailsObj   = JSON.parse(
        await fs.readFile(EMAILS_PATH, "utf8")
      ) as Record<string, string>;

      const output: Record<string, { email: string; accountCode: Hex; salt: string; address: string }> = {};

      for (const [id, email] of Object.entries(emailsObj)) {
        const code = await generateAccountCode();
        console.log(`\nGenerating guardian for ${email} (code=${code})…`);
        const { address, salt } = await computeGuardianAddress(account, code, email);
        console.log("  → computed address:", address);
        output[id] = { email, accountCode: code, salt, address };
      }

      const OUT_PATH = join(__dirname, "data", "guardians_addrs.json");
      await fs.writeFile(OUT_PATH, JSON.stringify(output, null, 2), "utf8");
      console.log("\n✅ Wrote guardian data to", OUT_PATH);
      process.exit(0);
    } catch (e) {
      console.error(e);
      process.exit(1);
    }
  })();
}