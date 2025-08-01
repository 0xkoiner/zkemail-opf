// script/produceProofs.ts
import fs from "fs/promises";
import path from "path";
import zke from "@zk-email/sdk";
import { generateEmailVerifierInputs } from "@zk-email/helpers";
import pkg from "js-sha3";
const { keccak_256 } = pkg;              // CJS → ESM bridge

/* paths --------------------------------------------------------- */
const EMAIL_DIR = "./emails";
const PROOF_DIR = "./proofs";
const GUARDIANS = JSON.parse(await fs.readFile("./script/data/guardians.json","utf8"));
const SALTS     = JSON.parse(await fs.readFile("./script/data/salts.json","utf8"));

/* constants ----------------------------------------------------- */
const WALLET       = "0x5615dEb798bb3e4Dfa0139dFa1B3D433cC23b72f".toLowerCase();
const BLUEPRINT_ID = "guardian_accept@v1";

/* helper -------------------------------------------------------- */
const sender = (raw:string)=>raw.match(/^From:.*<([^>]+)>/mi)?.[1]?.toLowerCase()||null;

/* main ---------------------------------------------------------- */
(async () => {
  await fs.mkdir(PROOF_DIR,{recursive:true});

  const sdk       = zke();                               // factory
  const blueprint = await sdk.getBlueprint(BLUEPRINT_ID);
  const prover    = blueprint.createProver({ isLocal:false }); // remote Groth16

  for (const f of (await fs.readdir(EMAIL_DIR)).filter(x=>x.endsWith(".eml"))) {
    const raw = await fs.readFile(path.join(EMAIL_DIR,f),"utf8");
    const mail= sender(raw);
    if (!mail || !(mail in GUARDIANS)) { console.warn("skip",f); continue; }

    const emailAuth   = GUARDIANS[mail];
    const accountSalt = SALTS[emailAuth.toLowerCase()];
    if (!accountSalt) { console.warn("no salt",mail); continue; }

    console.log("• proving", mail);

    /* externalInputs satisfy template + circuit vars */
    const proof = await prover.generateProof(
      raw,
      [
        { name:"ethAddr",     value: WALLET,      type:"bytes20", maxLength:20 },
        { name:"accountSalt", value: accountSalt, type:"bytes32", maxLength:32 }
      ]
    );

    await fs.writeFile(
      path.join(PROOF_DIR, `${emailAuth}.json`),
      JSON.stringify(proof,null,2)
    );
    console.log("  ✓", emailAuth);
  }
})();