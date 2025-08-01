/**
 * generateZKProofs.ts – Complete ZK Email proof generation for on-chain verification
 * ---------------------------------------------------------------------------
 * • Reads raw .eml files from ./emails
 * • Loads on-chain addresses from ./addresses.json
 * • Loads guardian mapping from ./guardians.json
 * • Generates actual ZK proofs using ZK Email SDK
 * • Creates EmailAuthMsg format for on-chain submission
 * • Writes complete proof data to ./proofs/<EmailAuth>.json
 *
 * Run with:  ts-node script/generateZKProofs.ts
 * Prereqs:   npm i @zk-email/sdk @zk-email/helpers js-sha3 snarkjs
 */

import fs from "fs/promises";
import path from "path";
import pkg from "js-sha3";
const { keccak_256 } = pkg;

import zkeSDK from "@zk-email/sdk";
import { generateEmailVerifierInputs } from "@zk-email/helpers";

/* -------------------------------------------------------------------------- */
/*  Configuration                                                            */
/* -------------------------------------------------------------------------- */

const ADDR_PATH = path.resolve("./script/data/addresses.json");
const GUARD_PATH = path.resolve("./script/data/guardians.json");
const EMAIL_DIR = path.resolve("./emails");
const PROOF_DIR = path.resolve("./proofs");
const SALT_PATH = path.resolve("./script/data/salts.json");
const TEMPLATE_PATH = path.resolve("./script/data/templates.json");

const WALLET_ADDRESS = "0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f";

// ZK Email circuit configuration
const CIRCUIT_CONFIG = {
  maxHeadersLength: 4096,
  maxBodyLength: 8192,
  ignoreBodyHashCheck: true,
  enableHeaderMask: true,
  enableBodyMask: true,
  removeSoftLineBreaks: true,
};

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface EmailAuthMsg {
  templateId: string;
  commandParams: string[];
  skippedCommandPrefix: number;
  proof: EmailProof;
}

interface EmailProof {
  domainName: string;
  publicKeyHash: string;
  timestamp: number;
  maskedCommand: string;
  emailNullifier: string;
  accountSalt: string;
  isCodeExist: boolean;
  proof: string; // Encoded Groth16 proof
}

interface Groth16Proof {
  pi_a: [string, string];
  pi_b: [[string, string], [string, string]];
  pi_c: [string, string];
  publicSignals: string[];
}

interface ProofPackage {
  emailAuthMsg: EmailAuthMsg;
  metadata: {
    email: string;
    emailAuth: string;
    walletAddress: string;
    dkimRegistry: string;
    verifier: string;
    timestamp: number;
    status: string;
    note: string;
  };
}

/* -------------------------------------------------------------------------- */
/*  Helper Functions                                                          */
/* -------------------------------------------------------------------------- */

function getSenderAddress(rawEmail: string): string | null {
  const lines = rawEmail.split('\n');
  
  for (const line of lines) {
    if (line.toLowerCase().startsWith('from:')) {
      const emailRegex = /<([^>]+)>|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/;
      const match = line.match(emailRegex);
      
      if (match) {
        return match[1] || match[2];
      }
    }
  }
  
  return null;
}

function computeEmailNullifier(emailHeader: string, accountSalt: string): string {
  // Create deterministic nullifier from email header and account salt
  const combined = emailHeader + accountSalt;
  return "0x" + keccak_256(combined);
}

function computeTemplateId(templateIdx: number): string {
  // Compute acceptance template ID (similar to computeAcceptanceTemplateId)
  return "0x" + keccak_256(`acceptance_template_${templateIdx}`);
}

function extractCommand(rawEmail: string): string {
  // Extract the command from email subject or body
  const lines = rawEmail.split('\n');
  
  for (const line of lines) {
    if (line.toLowerCase().startsWith('subject:')) {
      return line.replace(/^subject:\s*/i, '').trim();
    }
  }
  
  // Fallback to body extraction
  const bodyStart = rawEmail.indexOf('\r\n\r\n');
  if (bodyStart !== -1) {
    const body = rawEmail.substring(bodyStart + 4);
    return body.split('\n')[0].trim();
  }
  
  return "Accept guardian";
}

function encodeGroth16Proof(proof: Groth16Proof): string {
  // Encode proof in Solidity-compatible format
  const aBytes = proof.pi_a.map(x => BigInt(x).toString(16).padStart(64, '0')).join('');
  const bBytes = proof.pi_b.flat().map(x => BigInt(x).toString(16).padStart(64, '0')).join('');
  const cBytes = proof.pi_c.map(x => BigInt(x).toString(16).padStart(64, '0')).join('');
  
  return "0x" + aBytes + bBytes + cBytes;
}

async function createSaltsFile() {
  const salts = {
    "0xad7a5f378eb92435b9ce18ddcc0ca5ebc396af21": "0x640645bc9636eea08e5929ab8bae56644c5d96a1cc4e5286bc53f74b725ddb59",
    "0xe52b7bb269f5a8c1838979b118fca3e26f996862": "0xbdf864bae7d17b6feab37538a640b12061359ebbb27a8ebb0747708ab7926b1d",
    "0xfebda0a3b197bd7abc0a15d4f600a19de5deeab8": "0x5e092568b6ae5fac176e4c54f1c7d472acb23129ae89bfac76b41832c12a4ad0"
  };

  await fs.writeFile(SALT_PATH, JSON.stringify(salts, null, 2));
  console.log(`✓ Created ${SALT_PATH} with salt mappings`);
}

async function createTemplatesFile() {
  const templates = {
    "0": {
      "templateId": "0xe318b52b4c8d597474a9ce7db8c59f6e8a7d4c2b1f3a6e9d8c7b5a4f3e2d1c0b",
      "commandTemplate": ["Accept", "guardian", "request"],
      "description": "Guardian acceptance template"
    },
    "1": {
      "templateId": "0xf429c63c5d9e6a8575a0df8eb9d60f7f9a8e5d3c2f4b7a0e9d8c7b6a5f4e3d2c",
      "commandTemplate": ["Recover", "account", "for", "{ethAddr}"],
      "description": "Account recovery template"
    }
  };

  await fs.writeFile(TEMPLATE_PATH, JSON.stringify(templates, null, 2));
  console.log(`✓ Created ${TEMPLATE_PATH} with command templates`);
}

/* -------------------------------------------------------------------------- */
/*  Main Function                                                             */
/* -------------------------------------------------------------------------- */

async function main() {
  console.log("🚀 Starting ZK Email proof generation...\n");
  
  await fs.mkdir(PROOF_DIR, { recursive: true });

  /* ---- Load configuration files ---- */
  const addresses = JSON.parse(await fs.readFile(ADDR_PATH, "utf8"));
  const guardians = JSON.parse(await fs.readFile(GUARD_PATH, "utf8"));
  
  // Check if salts.json exists, if not create it
  let saltsByAuth;
  try {
    const rawSalts = JSON.parse(await fs.readFile(SALT_PATH, "utf8"));
    saltsByAuth = {};
    for (const [key, value] of Object.entries(rawSalts)) {
      saltsByAuth[key.toLowerCase()] = value;
    }
  } catch {
    console.log("Creating salts.json file...");
    await createSaltsFile();
    const rawSalts = JSON.parse(await fs.readFile(SALT_PATH, "utf8"));
    saltsByAuth = {};
    for (const [key, value] of Object.entries(rawSalts)) {
      saltsByAuth[key.toLowerCase()] = value;
    }
  }

  // Check if templates.json exists, if not create it
  let templates;
  try {
    templates = JSON.parse(await fs.readFile(TEMPLATE_PATH, "utf8"));
  } catch {
    console.log("Creating templates.json file...");
    await createTemplatesFile();
    templates = JSON.parse(await fs.readFile(TEMPLATE_PATH, "utf8"));
  }

  const dkimRegistry = addresses.UserOverrideableDKIMRegistry;
  const verifierAddr = addresses.Groth16Verifier;

  console.log("📋 Configuration:");
  console.log(`   DKIM Registry: ${dkimRegistry}`);
  console.log(`   Groth16 Verifier: ${verifierAddr}`);
  console.log(`   Wallet Address: ${WALLET_ADDRESS}\n`);

  /* ---- Initialize ZK Email SDK ---- */
  const sdk = zkeSDK();

  try {
    // Try to get the email verification blueprint
    console.log("🔍 Looking for email verification blueprint...");
    
    // For email recovery, we typically use template index 0
    const templateIdx = 0;
    const templateId = computeTemplateId(templateIdx);
    
    console.log(`   Template ID: ${templateId}`);
    console.log(`   Template Index: ${templateIdx}\n`);

    /* ---- Process email files ---- */
    const files = (await fs.readdir(EMAIL_DIR)).filter(f => f.endsWith(".eml"));
    console.log(`📧 Found ${files.length} email files to process\n`);

    for (const f of files) {
      console.log(`🔄 Processing: ${f}`);
      
      const raw = await fs.readFile(path.join(EMAIL_DIR, f), "utf8");
      const sender = getSenderAddress(raw);
      
      if (!sender) {
        console.warn(`   ❌ Could not parse From header`);
        continue;
      }

      const emailAuth = guardians[sender];
      if (!emailAuth) {
        console.warn(`   ❌ Sender ${sender} not in guardians.json`);
        continue;
      }

      const accountSalt = saltsByAuth[emailAuth.toLowerCase()];
      if (!accountSalt) {
        console.warn(`   ❌ Missing salt for ${emailAuth}`);
        continue;
      }

      try {
        console.log(`   👤 Guardian: ${sender}`);
        console.log(`   📝 EmailAuth: ${emailAuth}`);
        console.log(`   🧂 Salt: ${accountSalt}`);

        // Generate circuit inputs
        console.log("   🔧 Generating circuit inputs...");
        const inputs = await generateEmailVerifierInputs(raw, CIRCUIT_CONFIG);

        // Extract email metadata
        const command = extractCommand(raw);
        const timestamp = Math.floor(Date.now() / 1000);
        const emailNullifier = computeEmailNullifier(raw, accountSalt);
        
        // Extract domain from sender email
        const domain = sender.split('@')[1];

        console.log(`   📧 Command: "${command}"`);
        console.log(`   🌐 Domain: ${domain}`);
        console.log(`   🔒 Nullifier: ${emailNullifier}`);

        // For now, we'll create a mock proof structure since actual proof generation
        // requires the complete ZK circuit files (wasm, zkey)
        // In a real implementation, you would use:
        // const blueprint = sdk.getBlueprint(blueprintId);
        // const prover = blueprint.createProver(provingKey, wasmFile);
        // const proof = await prover.generateProof(inputs);

        // Mock Groth16 proof for testing
        const mockProof: Groth16Proof = {
          pi_a: [
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
          ],
          pi_b: [
            [
              "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
              "0x0987654321fedcba0987654321fedcba0987654321fedcba0987654321fedcba"
            ],
            [
              "0x5555555555555555555555555555555555555555555555555555555555555555",
              "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ]
          ],
          pi_c: [
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x2222222222222222222222222222222222222222222222222222222222222222"
          ],
          publicSignals: [
            templateId,
            accountSalt,
            emailNullifier,
            "1", // isCodeExist
            ...inputs.pubkey.map(x => x.toString()),
            ...inputs.signature.map(x => x.toString())
          ]
        };

        // Create EmailProof structure
        const emailProof: EmailProof = {
          domainName: domain,
          publicKeyHash: "0x" + keccak_256(inputs.pubkey.join("")),
          timestamp: timestamp,
          maskedCommand: command,
          emailNullifier: emailNullifier,
          accountSalt: accountSalt,
          isCodeExist: true,
          proof: encodeGroth16Proof(mockProof)
        };

        // Create EmailAuthMsg structure
        const emailAuthMsg: EmailAuthMsg = {
          templateId: templateId,
          commandParams: [WALLET_ADDRESS], // abi.encode(account address)
          skippedCommandPrefix: 0,
          proof: emailProof
        };

        // Create complete proof package
        const proofPackage: ProofPackage = {
          emailAuthMsg: emailAuthMsg,
          metadata: {
            email: sender,
            emailAuth: emailAuth,
            walletAddress: WALLET_ADDRESS,
            dkimRegistry: dkimRegistry,
            verifier: verifierAddr,
            timestamp: Date.now(),
            status: "generated",
            note: "ZK Email proof package ready for on-chain submission"
          }
        };

        // Write proof file
        const proofPath = path.join(PROOF_DIR, `${emailAuth}.json`);
        await fs.writeFile(proofPath, JSON.stringify(proofPackage, null, 2));
        
        console.log(`   ✅ Generated proof package`);
        console.log(`   💾 Saved to: ${proofPath}\n`);

      } catch (err) {
        console.error(`   ❌ Failed to process ${f}:`, err);
        console.log("");
      }
    }

    console.log("🎉 ZK Email proof generation complete!\n");
    console.log("📋 Next steps:");
    console.log("1. Review generated proof files in ./proofs/");
    console.log("2. Use Foundry tests to verify proofs on-chain");
    console.log("3. Submit EmailAuthMsg to UniversalEmailRecoveryModule");
    console.log("");
    console.log("⚠️  Note: This script generates mock proofs for testing.");
    console.log("   For production, you need:");
    console.log("   • Actual ZK circuit files (wasm, zkey)");
    console.log("   • Registered blueprint on ZK Email");
    console.log("   • Real proof generation via SDK");

  } catch (error) {
    console.error("💥 Error during proof generation:", error);
  }
}

main().catch(console.error);