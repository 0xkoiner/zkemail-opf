import fs from "fs/promises";
import path from "path";
import { simpleParser } from "mailparser";
import { Resolver } from "dns/promises";
import { keccak256 } from "viem"; 

const EMAIL_DIR = "./emails";
const SALT_PATH = "./script/data/guardians_salt.json";
const OUTPUT_FILE = "./script/data/EmailProofs.json";

const ACCOUNT_ADDR = "0x5615dEb798bb3e4Dfa0139dFa1B3D433cC23b72f".toLowerCase();
const MASKED_CMD = `Accept guardian request for ${ACCOUNT_ADDR}`;

const resolver = new Resolver();

const keccakHex = (x: string | Buffer): string => {
  const bytes = typeof x === 'string' ? Buffer.from(x, 'utf8') : x;
  return keccak256(bytes);
};

function parseFolded(headerBlock: string) {
  return headerBlock.replace(/\r?\n[ \t]+/g, " "); 
}

function parseDkim(headerBlock: string) {
  const h = parseFolded(headerBlock);
  const d = /[;\s]d=([^;\s]+)/i.exec(h)?.[1];
  const s = /[;\s]s=([^;\s]+)/i.exec(h)?.[1];
  return { domain: d, selector: s };
}

async function publicKeyHash(selector: string, domain: string) {
  try {
    const groups = await resolver.resolveTxt(`${selector}._domainkey.${domain}`);
    const joined = groups.map(g => g.join("")).join(""); 
    const pMatch = joined.match(/p=([A-Za-z0-9/+]+=*)/);
    if (!pMatch) throw new Error("no p=");
    const raw = Buffer.from(pMatch[1], "base64");
    return keccakHex(raw); 
  } catch (e: any) {
    console.warn(`DNS ${selector}._domainkey.${domain}: ${e.message}`);
    return "0x"; 
  }
}

const nullifier = (msgId: string) => keccakHex(msgId.trim());

(async () => {
  try {
    let salts: Record<string, string> = {};
    try {
      salts = JSON.parse(await fs.readFile(SALT_PATH, "utf8"));
    } catch (e) {
      console.warn(`Salt file ${SALT_PATH} not found, using empty salts`);
    }

    const proofs: any = {};

    let files: string[];
    try {
      files = (await fs.readdir(EMAIL_DIR)).filter(f => f.endsWith(".eml"));
    } catch (e) {
      console.error(`Email directory ${EMAIL_DIR} not found`);
      return;
    }

    for (const file of files) {
      console.log(`Processing ${file}...`);
      
      const rawBuf = await fs.readFile(path.join(EMAIL_DIR, file));
      const rawStr = rawBuf.toString("utf8");
      const mail = await simpleParser(rawBuf);

      const from = mail.from?.value?.[0]?.address?.toLowerCase();
      if (!from) {
        console.warn(`${file}: no From address found`);
        continue;
      }

      const dkimBlock = rawStr.match(/DKIM-Signature:[\s\S]+?(?:\r?\n\r?\n|\r?\n--)/i)?.[0];
      if (!dkimBlock) {
        console.warn(`${file}: missing DKIM header`);
        continue;
      }

      const { domain, selector } = parseDkim(dkimBlock);
      if (!domain || !selector) {
        console.warn(`${file}: cannot parse d=/s= from DKIM`);
        continue;
      }

      console.log(`  Domain: ${domain}, Selector: ${selector}`);

      const pkHash = await publicKeyHash(selector, domain);
      const arcBlock = rawStr.match(/ARC-Seal:[\s\S]+?(?:\r?\n\r?\n|\r?\n--)/i)?.[0] || "";
      const ts = Number(/[;\s]t=(\d+)/.exec(arcBlock)?.[1]) ||
        Math.floor(new Date(mail.date || Date.now()).getTime() / 1000);

      proofs[from] = {
        domainName: domain,
        publicKeyHash: pkHash,
        timestamp: ts,
        maskedCommand: MASKED_CMD,
        emailNullifier: nullifier(mail.messageId || from + ts), 
        accountSalt: salts[from] ?? "0x",
        isCodeExist: true,
        proof: "0x"
      };
      
      console.log(`✓ extracted ${from}`);
    }

    const outputDir = path.dirname(OUTPUT_FILE);
    await fs.mkdir(outputDir, { recursive: true });

    await fs.writeFile(OUTPUT_FILE, JSON.stringify(proofs, null, 2));
    console.log(`\nWrote → ${OUTPUT_FILE}`);
    console.log(`Processed ${Object.keys(proofs).length} emails`);
  } catch (error) {
    console.error("Error processing emails:", error);
  }
})();