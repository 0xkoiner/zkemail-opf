
import fs from 'fs';
import { promises as dns } from 'dns';
import { keccak256 } from 'viem';

const emlPath = process.argv[2];
if (!emlPath) { console.error('pass .eml path'); process.exit(1); }
const raw = fs.readFileSync(emlPath, 'utf8');

const hdr = (raw.match(/^DKIM-Signature:[^\r\n]*(?:\r?\n[ \t].*)*/im) || [''])[0]
              .replace(/\r?\n[ \t]/g, '');        
const sel = (hdr.match(/s=([^;]+)/) || [])[1];
const dom = (hdr.match(/d=([^;]+)/) || [])[1];
if (!sel || !dom) {
  console.error('❌  DKIM s= or d= tag missing in e-mail');
  process.exit(1);
}

(async () => {
  const txt = (await dns.resolveTxt(`${sel}._domainkey.${dom}`)).flat().join('');
  const b64 = (txt.match(/p=([A-Za-z0-9+/=]+)/) || [])[1];
  if (!b64) throw new Error('❌  p= tag missing in DNS TXT');

  const hash = keccak256(Buffer.from(b64, 'base64'));
  console.log(hash);                 
})()
.catch(err => { console.error(err); process.exit(1); });