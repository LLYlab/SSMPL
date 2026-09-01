#!/usr/bin/env node
// SSMPL CLI (JavaScript / Node) — encrypt / add-password / decrypt.
//   node ssmpl-cli.js encrypt <password> <plaintextFile> [--hash SHA-256|SHA-512] [--iters N] [--cipher GCM|CBC-HMAC]
//   node ssmpl-cli.js addpass <blobJson> <name> <newPassword> <unlockPassword>
//   node ssmpl-cli.js decrypt <blobJson> <name> <password>
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { encryptItem, addPassword, decryptItem, b64e, b64d } from './ssmpl.js';

const [cmd, ...rest] = process.argv.slice(2);
const SALT = () => new Uint8Array(randomBytes(16));

function flags(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--hash') out.hash = argv[++i];
    else if (a === '--iters') out.iterations = Number(argv[++i]);
    else if (a === '--cipher') out.cipher = argv[++i] === 'CBC-HMAC' ? 'AES-256-CBC-HMAC-SHA256' : 'AES-256-GCM';
    else if (a === '--salt') out.salt = b64d(argv[++i]);
  }
  return out;
}
function cfgFrom(overrides, providedSalt) {
  return Object.assign({ hash: 'SHA-256', iterations: 250000, cipher: 'AES-256-GCM', salt: providedSalt }, overrides);
}

async function main() {
  if (cmd === 'encrypt') {
    const [password, file] = rest;
    if (!password || !file) return console.log('usage: encrypt <password> <plaintextFile> [flags]');
    const f = flags(rest.slice(2));
    const salt = f.salt || SALT();
    const cfg = cfgFrom(f, salt);
    const plaintext = readFileSync(file, 'utf8');
    const item = await encryptItem(plaintext, password, cfg);
    const blob = { ssmpl: 1, cipher: cfg.cipher, kdf: 'PBKDF2-HMAC', hash: cfg.hash, iterations: cfg.iterations, salt: b64e(salt), items: { [file.split(/[\\/]/).pop()]: item } };
    writeFileSync('ssmpl-lock.json', JSON.stringify(blob, null, 2));
    console.log('wrote ssmpl-lock.json  (salt=' + cfg.hash + '/' + cfg.iterations + 'iters/' + cfg.cipher + ')');
    console.log('item: ' + JSON.stringify(item, null, 2));
  } else if (cmd === 'addpass') {
    const [blobFile, name, newPw, unlockPw] = rest;
    const blob = JSON.parse(readFileSync(blobFile, 'utf8'));
    const cfg = cfgFrom({ hash: blob.hash, iterations: blob.iterations, cipher: blob.cipher }, b64d(blob.salt));
    const next = await addPassword(blob.items[name], newPw, unlockPw, cfg);
    blob.items[name] = next;
    writeFileSync(blobFile, JSON.stringify(blob, null, 2));
    console.log('added password "' + newPw + '" to "' + name + '" (no re-encryption).');
  } else if (cmd === 'decrypt') {
    const [blobFile, name, password] = rest;
    const blob = JSON.parse(readFileSync(blobFile, 'utf8'));
    const cfg = cfgFrom({ hash: blob.hash, iterations: blob.iterations, cipher: blob.cipher }, b64d(blob.salt));
    const plain = await decryptItem(blob.items[name], password, cfg);
    console.log(plain);
  } else {
    console.log('SSMPL CLI\n  encrypt <password> <file> [flags]\n  addpass <blob.json> <name> <newPw> <unlockPw>\n  decrypt <blob.json> <name> <password>');
  }
}
main().catch((e) => { console.error('ERROR: ' + e.message); process.exit(1); });
