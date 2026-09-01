#!/usr/bin/env node
import {
  b64e, b64d, deriveKey, encryptItem, decryptItem, addPassword, getKey, Lock,
} from '../src/ssmpl.js';
import { randomBytes } from 'node:crypto';

const SALT = new Uint8Array(randomBytes(16));
const CFG = { hash: 'SHA-256', iterations: 250000, cipher: 'AES-256-GCM', salt: SALT };
const CFG_SHA512 = { hash: 'SHA-512', iterations: 260000, cipher: 'AES-256-GCM', salt: SALT };
const CFG_CBC = { hash: 'SHA-256', iterations: 250000, cipher: 'AES-256-CBC-HMAC-SHA256', salt: SALT };

let pass = 0, fail = 0;
function check(name, cond) {
  if (cond) { pass++; console.log('  ok  ' + name); }
  else { fail++; console.log('FAIL  ' + name); }
}

console.log('# encrypt/decrypt round-trip (GCM)');
const item = await encryptItem('黄文正文·第一章 secret content', 'alpha', CFG);
check('decrypt with correct password', (await decryptItem(item, 'alpha', CFG)) === '黄文正文·第一章 secret content');
let threw = false; try { await decryptItem(item, 'nope', CFG); } catch (_) { threw = true; }
check('wrong password rejected', threw === true);

console.log('# multi-password (add 密本 without re-encrypt)');
const item2 = await addPassword(item, 'beta', 'alpha', CFG);
check('original password still works', (await decryptItem(item2, 'alpha', CFG)) === '黄文正文·第一章 secret content');
check('added password works', (await decryptItem(item2, 'beta', CFG)) === '黄文正文·第一章 secret content');
check('item still has exactly one ciphertext (books grew only)', Array.isArray(item2.books) && item2.books.length === 2 && item2.ct === item.ct && item2.iv === item.iv);

console.log('# different config (SHA-512 + 260k iters, GCM)');
const itemA = await encryptItem('你好 world 123', 'p1', CFG_SHA512);
check('SHA-512 config round-trips', (await decryptItem(itemA, 'p1', CFG_SHA512)) === '你好 world 123');
check('SHA-512 wrong password rejected', await (async () => { try { await decryptItem(itemA, 'x', CFG_SHA512); return false; } catch (_) { return true; } })());

console.log('# CBC+HMAC (encrypt-then-MAC)');
const itemC = await encryptItem('cbc-mode data 数据', 'cbc1', CFG_CBC);
check('CBC+HMAC round-trips', (await decryptItem(itemC, 'cbc1', CFG_CBC)) === 'cbc-mode data 数据');
check('CBC+HMAC wrong password rejected', await (async () => { try { await decryptItem(itemC, 'x', CFG_CBC); return false; } catch (_) { return true; } })());

console.log('# frontend Lock (blob JSON round-trip)');
const blob = { ssmpl: 1, cipher: 'AES-256-GCM', kdf: 'PBKDF2-HMAC', hash: 'SHA-256', iterations: 250000, salt: b64e(SALT), items: { story: item, story2: itemC } };
const serialized = JSON.stringify(blob);
const re = JSON.parse(serialized);                       // simulate the hosted JSON file
const lock = new Lock(re);
check('not unlocked initially', !lock.isUnlocked());
check('unlock wrong password fails', (await lock.unlock('zzz')) === false);
check('unlock correct password succeeds (alpha)', (await lock.unlock('alpha')) === true);
check('decrypt story', (await lock.decrypt('story')) === '黄文正文·第一章 secret content');

const lockCbc = new Lock(JSON.parse(JSON.stringify({ ...blob, items: { c: itemC }, cipher: 'AES-256-CBC-HMAC-SHA256' })));
check('Lock(unlock beta on CBC item) succeeds', (await lockCbc.unlock('cbc1')) === true);
check('Lock(decrypt CBC item)', (await lockCbc.decrypt('c')) === 'cbc-mode data 数据');

console.log('# setters');
const lock2 = new Lock(re).setHash('SHA-256').setIterations(250000).setCipher('AES-256-GCM');
check('setters return this (chainable)', lock2 instanceof Lock);

console.log(`\n== ${pass} passed, ${fail} failed ==`);
process.exit(fail ? 1 : 0);
