#!/usr/bin/env node
// SSMPL — Static Site · Multi-Password Lock  (JavaScript / WebCrypto)
// Works in Node >= 18 (globalThis.crypto is WebCrypto) and in browsers.
//
// Backend (encrypt / 密本 / multi-password) and Frontend (unlock / decrypt) share this one module.
// The online payload is the blob JSON; a reader needs a valid password to recover the plaintext.
//
// Config (settable via setConfig / config object):
//   hash       : "SHA-256" | "SHA-512"
//   iterations : int (KDF cost)
//   cipher     : "AES-256-GCM" | "AES-256-CBC-HMAC-SHA256"
//   salt       : Uint8Array (public salt)

const subtle = (globalThis.crypto || {}).subtle;
if (!subtle) throw new Error('SSMPL: WebCrypto (crypto.subtle) is required.');

const DEFAULT_CONFIG = {
  hash: 'SHA-256',
  iterations: 250000,
  cipher: 'AES-256-GCM',
  salt: null, // must be set (16 bytes) before use; or a fixed salt provided by caller
};

// ---------- bytes / base64 ----------
function b64e(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function b64d(b64) {
  const bin = atob(b64);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function xorBytes(a, b) {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}
function toBytes(s) { return new TextEncoder().encode(s); }
function fromBytes(u) { return new TextDecoder().decode(u); }
function normalizeConfig(cfg) {
  const c = Object.assign({}, DEFAULT_CONFIG, cfg || {});
  if (!c.salt || c.salt.length < 8) throw new Error('SSMPL: config.salt must be set (>=8 bytes).');
  return c;
}

// ---------- one-way KDF: P = PBKDF2(password, salt, iterations, 32) ----------
async function deriveKey(password, cfg) {
  const c = normalizeConfig(cfg);
  const km = await subtle.importKey('raw', toBytes(String(password)), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: c.salt, iterations: c.iterations, hash: c.hash },
    km, 256);
  return new Uint8Array(bits); // P (32 bytes)
}

// ---------- two-way symmetric cipher ----------
async function macKeyFromK(K) {
  // deterministic mac key for CBC+HMAC mode (cross-language compatible)
  const label = toBytes('SSMPL.HMAC');
  const data = new Uint8Array(K.length + label.length);
  data.set(K); data.set(label, K.length);
  const d = await subtle.digest('SHA-256', data);
  return new Uint8Array(d);
}
async function hmac(key, msg) {
  const k = await subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await subtle.sign('HMAC', k, msg);
  return new Uint8Array(sig);
}

async function encryptBytes(plain, K, cfg) {
  const c = normalizeConfig(cfg);
  if (c.cipher === 'AES-256-CBC-HMAC-SHA256') {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    const encKey = await subtle.importKey('raw', K, { name: 'AES-CBC' }, false, ['encrypt']);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, encKey, toBytes(plain)));
    const mkey = await macKeyFromK(K);
    const macInput = new Uint8Array(iv.length + ct.length);
    macInput.set(iv); macInput.set(ct, iv.length);
    const mac = await hmac(mkey, macInput);
    return { iv: b64e(iv), ct: b64e(ct), mac: b64e(mac) };
  } else { // AES-256-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await subtle.importKey('raw', K, { name: 'AES-GCM' }, false, ['encrypt']);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, toBytes(plain)));
    const tag = ct.slice(ct.length - 16);          // last 16 bytes = auth tag
    const body = ct.slice(0, ct.length - 16);
    return { iv: b64e(iv), ct: b64e(body), tag: b64e(tag) };
  }
}
async function decryptBytes(item, K, cfg) {
  const c = normalizeConfig(cfg);
  if (c.cipher === 'AES-256-CBC-HMAC-SHA256') {
    const mkey = await macKeyFromK(K);
    const macInput = new Uint8Array(b64d(item.iv).length + b64d(item.ct).length);
    macInput.set(b64d(item.iv)); macInput.set(b64d(item.ct), b64d(item.iv).length);
    const expect = await hmac(mkey, macInput);
    if (!timingEq(expect, b64d(item.mac))) throw new Error('SSMPL: MAC mismatch (wrong key).');
    const encKey = await subtle.importKey('raw', K, { name: 'AES-CBC' }, false, ['decrypt']);
    const plain = await subtle.decrypt({ name: 'AES-CBC', iv: b64d(item.iv) }, encKey, b64d(item.ct));
    return fromBytes(new Uint8Array(plain));
  } else { // AES-256-GCM
    const key = await subtle.importKey('raw', K, { name: 'AES-GCM' }, false, ['decrypt']);
    const ct = b64d(item.ct), tag = b64d(item.tag);
    const combined = new Uint8Array(ct.length + tag.length);
    combined.set(ct); combined.set(tag, ct.length);
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: b64d(item.iv) }, key, combined);
    return fromBytes(new Uint8Array(plain));
  }
}
function timingEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

// ---------- 密本 = P XOR K ----------
function computeBook(P, K) { return xorBytes(P, K); }

// ---------- backend operations ----------
async function unlockKey(item, P, cfg) {
  // try each 密本: K = P XOR 密本, then verify by decrypting
  for (const bk of item.books) {
    const K = xorBytes(P, b64d(bk));
    try { await decryptBytes(item, K, cfg); return K; } catch (_) { /* next 密本 */ }
  }
  return null;
}

async function encryptItem(plaintext, password, cfg) {
  const c = normalizeConfig(cfg);
  const K = crypto.getRandomValues(new Uint8Array(32));  // random content key
  const item = await encryptBytes(plaintext, K, c);
  const P = await deriveKey(password, c);
  item.books = [b64e(computeBook(P, K))];
  return item;
}

async function getKey(item, password, cfg) {
  const c = normalizeConfig(cfg);
  const P = await deriveKey(password, c);
  return await unlockKey(item, P, c);
}

async function decryptItem(item, password, cfg) {
  const K = await getKey(item, password, cfg);
  if (!K) throw new Error('SSMPL: wrong password (no 密本 decrypts).');
  return decryptBytes(item, K, cfg);
}

async function addPassword(item, newPassword, unlockPassword, cfg) {
  const K = await getKey(item, unlockPassword, cfg);
  if (!K) throw new Error('SSMPL: unlockPassword is wrong.');
  const P = await deriveKey(newPassword, cfg);
  const next = JSON.parse(JSON.stringify(item)); // deep copy so we don't mutate caller's item
  if (!next.books) next.books = [];
  next.books.push(b64e(computeBook(P, K)));
  return next;
}

// Revoke access for a given password on ONE item: drop that password's 密本 (no re-encrypt).
async function removePassword(item, password, cfg) {
  const c = normalizeConfig(cfg);
  const P = await deriveKey(password, c);
  const next = JSON.parse(JSON.stringify(item));
  const keep = [];
  for (const bk of next.books || []) {
    const K = xorBytes(P, b64d(bk));
    let mine = false;
    try { await decryptBytes(next, K, c); mine = true; } catch (_) { }
    if (!mine) keep.push(bk);                     // a book that decrypts = this password's -> drop
  }
  next.books = keep;
  return next;
}

// ---------- frontend lock (load a blob, unlock with a password, decrypt) ----------
class Lock {
  constructor(blob, cfg) {
    this.blob = blob;               // the hosted JSON payload (authoritative source of truth)
    this.config = Object.assign({}, cfg || {}); // only user overrides live here
    this._P = null;                 // cached derived key after a successful unlock
    this._map = {};                 // name -> item
    (function (self) {
      Object.keys(blob.items || {}).forEach(function (n) { self._map[n] = blob.items[n]; });
    })(this);
  }
  setConfig(cfg) { this.config = Object.assign({}, this.config, cfg || {}); this._P = null; return this; }
  setHash(h) { this.config.hash = h; this._P = null; return this; }
  setIterations(n) { this.config.iterations = n; this._P = null; return this; }
  setCipher(c) { this.config.cipher = c; this._P = null; return this; }

  async unlock(password) {
    // Build the effective config from the blob, letting only explicit user overrides win.
    const cfg = Object.assign({}, DEFAULT_CONFIG, {
      salt: this.blob.salt ? b64d(this.blob.salt) : this.config.salt,
      hash: this.blob.hash || DEFAULT_CONFIG.hash,
      iterations: this.blob.iterations || DEFAULT_CONFIG.iterations,
      cipher: this.blob.cipher || DEFAULT_CONFIG.cipher,
    }, this.config);
    const names = Object.keys(this._map);
    const P = await deriveKey(String(password), cfg);
    for (const n of names) {
      const K = await unlockKey(this._map[n], P, cfg);
      if (K) { this._P = P; this._cfg = cfg; return true; }
    }
    return false;
  }
  isUnlocked() { return this._P !== null; }
  async decrypt(name) {
    if (!this._P) throw new Error('SSMPL: not unlocked yet.');
    const item = this._map[name];
    if (!item) throw new Error('SSMPL: item not found: ' + name);
    const K = await unlockKey(item, this._P, this._cfg);
    if (!K) throw new Error('SSMPL: cannot decrypt item (wrong key).');
    return decryptBytes(item, K, this._cfg);
  }
}

export {
  DEFAULT_CONFIG, b64e, b64d, deriveKey, encryptBytes, decryptBytes, computeBook,
  encryptItem, getKey, decryptItem, addPassword, removePassword, Lock, xorBytes,
};
