#!/usr/bin/env node
// Cross-language interop: generate JS fixtures (fixed salt+password) and verify Python fixtures.
import { writeFileSync, readFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { b64e, b64d, encryptItem, decryptItem } from '../src/ssmpl.js';

const DIR = join(import.meta.dirname, '..', '..', 'test-interop');
mkdirSync(DIR, { recursive: true });

const SALT = new Uint8Array(16); for (let i = 0; i < 16; i++) SALT[i] = i;
const PW = 'interop-pw';
const PLAIN = '跨语言互通测试 SSMPL interop';
const CFG = { hash: 'SHA-256', iterations: 1000, cipher: 'AES-256-GCM', salt: SALT };
const CFG_CBC = { hash: 'SHA-256', iterations: 1000, cipher: 'AES-256-CBC-HMAC-SHA256', salt: SALT };

async function main() {
  // --- generate JS fixtures ---
  const gcm = await encryptItem(PLAIN, PW, CFG);
  const cbc = await encryptItem(PLAIN, PW, CFG_CBC);
  writeFileSync(join(DIR, 'js_gcm.json'), JSON.stringify(gcm, null, 2));
  writeFileSync(join(DIR, 'js_cbc.json'), JSON.stringify(cbc, null, 2));
  console.log('wrote js_gcm.json / js_cbc.json');

  // --- verify Python fixtures (the other direction) ---
  if (exists(join(DIR, 'py_gcm.json'))) {
    const pyGcm = JSON.parse(readFileSync(join(DIR, 'py_gcm.json'), 'utf8'));
    console.log((await decryptItem(pyGcm, PW, CFG)) === PLAIN
      ? '  ok  Python->JS GCM decrypt' : 'FAIL  Python->JS GCM decrypt');
  } else console.log('  -    Python GCM fixture not present, skipping');
  if (exists(join(DIR, 'py_cbc.json'))) {
    const pyCbc = JSON.parse(readFileSync(join(DIR, 'py_cbc.json'), 'utf8'));
    console.log((await decryptItem(pyCbc, PW, CFG_CBC)) === PLAIN
      ? '  ok  Python->JS CBC decrypt' : 'FAIL  Python->JS CBC decrypt');
  } else console.log('  -    Python CBC fixture not present, skipping');
}
function exists(p) { try { readFileSync(p); return true; } catch (_) { return false; } }
main().catch((e) => { console.error(e); process.exit(1); });
