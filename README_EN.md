# SSMPL — Static Site · Multi-Password Lock

**Put real access control on a static site. No server. No backend. No leaked plaintext.**

SSMPL is a tiny, cross-language toolkit that lets you **lock any content on a fully static
website** (GitHub Pages, Netlify, itch.io, …) behind **one of several passwords**, using a
password-based **key-wrapping** scheme we call the **密本 (cipher-book)**.

Anyone can download your whole site — it's just static files. But without a valid password,
the content is unreadable ciphertext. And because the scheme is *password-based*, you never need
a database, an auth endpoint, or anything to run server-side.

> **One sentence:** *"It gives a no-backend static blog something no static site should be able to
> have: real, multi-password content gates."*

---

## Why it's worth a look

| | |
|---|---|
| 🚫 **No server, no cost** | Runs entirely on static hosting. Nothing to operate, nothing to hack. |
| 🔐 **Real crypto, not obfuscation** | AES-256-GCM / AES-256-CBC+HMAC for the content — not base64 or a scrambled XOR key. |
| 🧠 **The cipher-book trick** | Content is encrypted with a **random key K**; passwords only wrap K through the **密本**. So you can **change or add a password without re-encrypting a single byte** of content. *It's a multi-password lock.* |
| 🕵️ **The password never leaves the browser** | One-way KDF (PBKDF2-HMAC-SHA256/512). Nothing is stored, nothing is transmitted, there's no server side to leak from. |
| ⚡ **The cheapest possible payload** | One ciphertext per article, **not per user** → **O(articles)**, not O(users × articles). Re-keying costs one XOR. |
| 🌍 **Three languages, one spec** | JavaScript (browser WebCrypto + Node), Python, C++ (OpenSSL). Fully interoperable. |
| 🎛️ **Configurable** | Set the KDF hash (`SHA-256`/`SHA-512`), the **iteration count**, and the cipher (`AES-256-GCM`/`AES-256-CBC-HMAC-SHA256`). |

---

## How it works (the 密本 / cipher-book)

Two layers, so re-keying is cheap and the password stays one-way:

```
content  ......  AES-256-GCM / AES-256-CBC+HMAC (random key K)  ....  TWO-WAY / reversible
password ......  PBKDF2-HMAC-SHA256/SHA512(password, salt, iters) -> P   ONE-WAY / irreversible
cipher-book  =  P XOR K      ("difference" between the encrypted password and the content key)

to read  =  type password -> P -> K = P XOR cipher-book -> try decrypt
           if that fails, try the next cipher-book   (multi-password)
```

- Because the **cipher-book only wraps K** (which is independent of any password), you can
  **swap / add passwords by recomputing `cipher-book = P_new XOR K`** — the ciphertext never changes.
- The **password is a one-way secret**: you can never recover it from `P`.
- The **content key is two-way**: an authorized reader gets it back and decrypts the article.

---

## Hosted payload (the JSON you publish)

```jsonc
{
  "ssmpl": 1,
  "cipher": "AES-256-GCM",            // or "AES-256-CBC-HMAC-SHA256"
  "kdf": "PBKDF2-HMAC",
  "hash": "SHA-256",                  // or "SHA-512"
  "iterations": 250000,
  "salt": "<base64>",
  "items": {
    "<name>": { "iv": "…", "ct": "…", "tag": "…" | "mac": "…",
                "books": ["<base64 cipher-book>", "…"] }   // one per authorized password
  }
}
```

---

## Config (each language)

| field | values | notes |
|---|---|---|
| `hash` | `SHA-256` / `SHA-512` | one-way password KDF hash |
| `iterations` | integer | KDF cost; higher = slower offline brute-force |
| `cipher` | `AES-256-GCM` / `AES-256-CBC-HMAC-SHA256` | content cipher (GCM is authenticated & recommended) |
| `salt` | bytes | public salt, fixed per lock |

---

## Quickstart

### JavaScript (browser front-end decrypt + Node back-end)

```js
import { Lock, encryptItem, addPassword, decryptItem, b64e } from './src/ssmpl.js';

// backend: encrypt + add another password
const salt = crypto.getRandomValues(new Uint8Array(16));
const cfg  = { hash:'SHA-256', iterations:250000, cipher:'AES-256-GCM', salt };
let item   = await encryptItem('top-secret 黄文', 'passwordA', cfg);
item       = await addPassword(item, 'passwordB', 'passwordA', cfg);   // no re-encryption

const blob = { ssmpl:1, cipher:cfg.cipher, kdf:'PBKDF2-HMAC', hash:cfg.hash,
               iterations:cfg.iterations, salt:b64e(salt), items:{ story:item } };

// frontend: reader unlocks & decrypts
const lock = new Lock(JSON.parse(JSON.stringify(blob)));
await lock.unlock('passwordB');               // false if wrong
const text = await lock.decrypt('story');
```

### Python

```python
from ssmpl import Config, encrypt_item, add_password, Lock
cfg = Config(hash="SHA-256", iterations=250000, cipher="AES-256-GCM", salt=bytes(range(16)))
item = encrypt_item("top-secret 黄文", "passwordA", cfg)
item = add_password(item, "passwordB", "passwordA", cfg)
lock = Lock({"ssmpl":1,"cipher":cfg.cipher,"kdf":"PBKDF2-HMAC","hash":cfg.hash,
             "iterations":cfg.iterations,"salt":b64e(cfg.salt),"items":{"story":item}})
lock.unlock("passwordB"); print(lock.decrypt("story"))
```

### C++ (OpenSSL)

```bash
cd cpp && cmake -B build && cmake --build build
./build/test_ssmpl        # round-trip + multi-password + GCM/CBC
./build/ssmpl_cli encrypt passwordA article.txt
./build/ssmpl_cli addpass ssmpl-lock.json article.txt passwordB passwordA
./build/ssmpl_cli decrypt ssmpl-lock.json article.txt passwordB
```

---

## Tests

```bash
node js/test/test.js              # JS core (16 cases)
py -3.9 python/tests/test_ssmpl.py # Python (16 cases)
node js/test/interop.mjs          # JS <-> Python, GCM + CBC, both directions
```

> **Note on C++:** in this repo's dev environment a C++ compiler + OpenSSL weren't available, so
> `cpp/` is written to the standard OpenSSL API and ships with `CMakeLists.txt` + a self-test, but
> was **not compiled here**. It uses the exact same algorithms as JS/Python and interoperates.

---

## Honest boundaries ("what it is NOT")

- This is **access gating / strong encryption for a static site**, not a **per-user authorization
  system**. There are no accounts, no revocation, no per-user keys.
- The payload is public, so an attacker can **offline brute-force the password** by testing
  `K = P(password) XOR cipher-book` against the cipher's auth tag. Security = **password entropy ×
  KDF cost**. Use a strong password and a high iteration count.
- For fine-grained "user A sees this, user B sees that", you need a backend.

---

## License

MIT
