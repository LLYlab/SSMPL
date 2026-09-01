# SSMPL — 静态站·多密码锁 / Static Site · Multi-Password Lock

<div align="center">

<a href="#中文"><kbd>🇨🇳 中文</kbd></a>
&nbsp;&nbsp;·&nbsp;&nbsp;
<a href="#english"><kbd>🌐 English</kbd></a>

</div>

---

<a id="中文"></a>

## 中文

给**纯静态网站**（GitHub Pages 等、无后端）加“密码门禁”的极简工具。核心是**密码基密钥封装（密本）**：整站可任意下载，但**没有密码就读不出正文**；密码本身**单向、不入库、不上传**；正文用**双向（对称）**密钥加密，授权者可还原。

三语言实现（算法、格式互通）：**JavaScript**（浏览器可用 WebCrypto）· **Python** · **C++**（OpenSSL）。

> 🌟 **一句话：** “让没有后端的静态博客，做到本该只有后端才有的——**真正的多密码内容门禁**。”

### 这玩意儿凭什么值得用（吹一吹）

|  |  |
|---|---|
| 🚫 **无后端 / 零成本** | 纯静态托管就能跑。没有服务器要运维，也没有服务器可被攻击。 |
| 🔐 **真加密，不是糊弄** | 正文用 AES-256-GCM / AES-256-CBC+HMAC——不是 base64，也不是一个写死的异或 key。 |
| 🧠 **密本（密钥封装）杀手锏** | 正文用**随机密钥 K** 加密，密码只通过**密本**去包 K。所以**换密码 / 加一个密码，正文一个字节都不用重加密**——这是真正的“多密码锁”。 |
| 🕵️ **密码永不离开用户浏览器** | 单向 KDF(PBKDF2-HMAC-SHA256/512)。不落盘、不上传、**没有后端可被拖库**。 |
| ⚡ **在线载荷最省** | **每篇一个密文**，而不是每用户一份 → **O(篇数)**，不是 O(用户×篇数)；换钥成本 = 一次异或。 |
| 🌍 **三语言一套规格** | JS(浏览器 WebCrypto + Node)· Python · C++(OpenSSL)，**完全互通**。 |
| 🎛️ **可配置** | KDF 哈希(SHA-256/512)、**迭代次数**、加密方式(AES-256-GCM / AES-256-CBC-HMAC-SHA256)都可设。 |

### 一句话原理

```
正文 ...... AES-256-GCM / AES-256-CBC+HMAC 加密(随机密钥 K) ..........  双向可逆
密码 ...... PBKDF2-HMAC-SHA256/SHA512(password, salt, iters) -> P .  单向不可逆
密本(book) = P XOR K     （“加密后密码 与 密钥 之差”，公开存储）
读取       = 输入密码 -> P -> K = P XOR 密本 -> 尝试解密；失败则试下一个密本
```

- **换密码 / 加密码**：只重算 `密本 = P_new XOR K`，**正文完全不用重加密**（多密码锁）。
- 在线载荷 **O(篇数)**，不是 O(用户×篇数)。

### 在线载荷格式（你要托管的那份 JSON）

```jsonc
{
  "ssmpl": 1,
  "cipher": "AES-256-GCM",          // 或 "AES-256-CBC-HMAC-SHA256"
  "kdf": "PBKDF2-HMAC",
  "hash": "SHA-256",                // 或 "SHA-512"
  "iterations": 250000,
  "salt": "<base64>",
  "items": { "<名称>": { "iv": "...", "ct": "...", "tag": "..."|"mac": "...", "books": ["<base64 密本>", ...] } }
}
```

### 配置（三语言都可设置）

| 字段 | 值 | 说明 |
|---|---|---|
| `hash` | `SHA-256` / `SHA-512` | 密码 KDF 哈希 |
| `iterations` | 整数 | KDF 代价（越大越抗离线爆破） |
| `cipher` | `AES-256-GCM` / `AES-256-CBC-HMAC-SHA256` | 正文加密方式（GCM 推荐，认证加密） |
| `salt` | bytes | 公开盐（每个 lock 固定） |

### JavaScript（浏览器前端解密 + Node 后端）

`js/src/ssmpl.js`（ESM，浏览器用 `globalThis.crypto`/WebCrypto，Node≥18 同样可用）。

```js
import { Lock, encryptItem, addPassword, decryptItem, b64e } from './src/ssmpl.js';

// ---- 后端：加密 + 多密码 ----
const salt = crypto.getRandomValues(new Uint8Array(16));          // 生成盐
const cfg = { hash:'SHA-256', iterations:250000, cipher:'AES-256-GCM', salt };
const item = await encryptItem('黄文正文…', '密码A', cfg);          // 一篇 → 含 1 个密本
const item2 = await addPassword(item, '密码B', '密码A', cfg);        // 再加一个密码（不重加密）

// 组装成要托管到网页的 blob（JSON 可序列化）
const blob = { ssmpl:1, cipher:cfg.cipher, kdf:'PBKDF2-HMAC', hash:cfg.hash,
               iterations:cfg.iterations, salt:b64e(salt), items:{ story: item2 } };

// ---- 前端：读取者解锁 + 解密 ----
const lock = new Lock(JSON.parse(JSON.stringify(blob)));           // 加载托管 JSON
await lock.unlock('密码B');                 // 校验密码（失败返回 false）
const plaintext = await lock.decrypt('story');   // 还原正文
```

前端即可用（`<script type="module">`）。

### Python

`python/ssmpl/`（pycryptodome）。

```python
from ssmpl import Config, encrypt_item, add_password, decrypt_item, Lock, b64e
cfg = Config(hash="SHA-256", iterations=250000, cipher="AES-256-GCM", salt=bytes(range(16)))
item = encrypt_item("黄文正文…", "密码A", cfg)
item = add_password(item, "密码B", "密码A", cfg)          # 不重加密
lock  = Lock({"ssmpl":1,"cipher":cfg.cipher,"kdf":"PBKDF2-HMAC","hash":cfg.hash,
              "iterations":cfg.iterations,"salt":b64e(cfg.salt),"items":{"story":item}})
lock.unlock("密码B"); print(lock.decrypt("story"))
```

### C++（OpenSSL）

`cpp/`，用 CMake 构建（需 OpenSSL）。

```bash
cd cpp && cmake -B build && cmake --build build
./build/test_ssmpl           # 自测：往返 + 多密码 + GCM/CBC
./build/ssmpl_cli encrypt 密码A article.txt
./build/ssmpl_cli addpass  ssmpl-lock.json article.txt 密码B 密码A
./build/ssmpl_cli decrypt  ssmpl-lock.json article.txt 密码B
```

### 测试

```bash
node js/test/test.js                # JS 核心（16 用例）
py -3.9 python/tests/test_ssmpl.py  # Python（16 用例）
# 跨语言互通（同一盐+密码，互相加解密）
node js/test/interop.mjs            # JS<->Python GCM/CBC
```

> 说明：本环境中 C++（g++/OpenSSL）未安装，`cpp/` 已按标准 OpenSSL 编写并带构建文件/自测，但**未在本机编译运行**；其与 JS/Python 采用完全相同算法，可互通。安装 `openssl` + 编译器后 `cmake --build` 即可。

### 边界（诚实版）

这是**静态站访问门禁 / 强混淆加密**，不是“多用户授权系统”。在线密文+密本公开，攻击者可**离线穷举密码**，安全性≈密码强度×KDF 代价。要真正的单用户权限需后端。

详见 [docs/SPEC.md](docs/SPEC.md)。

---

<a id="english"></a>

## English

**Put real access control on a static site. No server. No backend. No leaked plaintext.**

SSMPL is a tiny, cross-language toolkit that lets you **lock any content on a fully static
website** (GitHub Pages, Netlify, itch.io, …) behind **one of several passwords**, using a
password-based **key-wrapping** scheme we call the **密本 (cipher-book)**.

Anyone can download your whole site — it's just static files. But without a valid password,
the content is unreadable ciphertext. And because the scheme is *password-based*, you never need
a database, an auth endpoint, or anything to run server-side.

> **One sentence:** *"It gives a no-backend static blog something no static site should be able to
> have: real, multi-password content gates."*

### Why it's worth a look

| | |
|---|---|
| 🚫 **No server, no cost** | Runs entirely on static hosting. Nothing to operate, nothing to hack. |
| 🔐 **Real crypto, not obfuscation** | AES-256-GCM / AES-256-CBC+HMAC for the content — not base64 or a scrambled XOR key. |
| 🧠 **The cipher-book trick** | Content is encrypted with a **random key K**; passwords only wrap K through the **密本**. So you can **change or add a password without re-encrypting a single byte** of content. *It's a multi-password lock.* |
| 🕵️ **The password never leaves the browser** | One-way KDF (PBKDF2-HMAC-SHA256/512). Nothing is stored, nothing is transmitted, there's no server side to leak from. |
| ⚡ **The cheapest possible payload** | One ciphertext per article, **not per user** → **O(articles)**, not O(users × articles). Re-keying costs one XOR. |
| 🌍 **Three languages, one spec** | JavaScript (browser WebCrypto + Node), Python, C++ (OpenSSL). Fully interoperable. |
| 🎛️ **Configurable** | Set the KDF hash (`SHA-256`/`SHA-512`), the **iteration count**, and the cipher (`AES-256-GCM`/`AES-256-CBC-HMAC-SHA256`). |

### How it works (the 密本 / cipher-book)

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

### Hosted payload (the JSON you publish)

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

### Config (each language)

| field | values | notes |
|---|---|---|
| `hash` | `SHA-256` / `SHA-512` | one-way password KDF hash |
| `iterations` | integer | KDF cost; higher = slower offline brute-force |
| `cipher` | `AES-256-GCM` / `AES-256-CBC-HMAC-SHA256` | content cipher (GCM is authenticated & recommended) |
| `salt` | bytes | public salt, fixed per lock |

### Quickstart

**JavaScript (browser front-end decrypt + Node back-end)**

```js
import { Lock, encryptItem, addPassword, decryptItem, b64e } from './src/ssmpl.js';

// backend: encrypt + add another password
const salt = crypto.getRandomValues(new Uint8Array(16));
const cfg  = { hash:'SHA-256', iterations:250000, cipher:'AES-256-GCM', salt };
let item   = await encryptItem('top-secret secret', 'passwordA', cfg);
item       = await addPassword(item, 'passwordB', 'passwordA', cfg);   // no re-encryption

const blob = { ssmpl:1, cipher:cfg.cipher, kdf:'PBKDF2-HMAC', hash:cfg.hash,
               iterations:cfg.iterations, salt:b64e(salt), items:{ story:item } };

// frontend: reader unlocks & decrypts
const lock = new Lock(JSON.parse(JSON.stringify(blob)));
await lock.unlock('passwordB');               // false if wrong
const text = await lock.decrypt('story');
```

**Python**

```python
from ssmpl import Config, encrypt_item, add_password, Lock
cfg = Config(hash="SHA-256", iterations=250000, cipher="AES-256-GCM", salt=bytes(range(16)))
item = encrypt_item("top-secret secret", "passwordA", cfg)
item = add_password(item, "passwordB", "passwordA", cfg)
lock = Lock({"ssmpl":1,"cipher":cfg.cipher,"kdf":"PBKDF2-HMAC","hash":cfg.hash,
             "iterations":cfg.iterations,"salt":b64e(cfg.salt),"items":{"story":item}})
lock.unlock("passwordB"); print(lock.decrypt("story"))
```

**C++ (OpenSSL)**

```bash
cd cpp && cmake -B build && cmake --build build
./build/test_ssmpl        # round-trip + multi-password + GCM/CBC
./build/ssmpl_cli encrypt passwordA article.txt
./build/ssmpl_cli addpass ssmpl-lock.json article.txt passwordB passwordA
./build/ssmpl_cli decrypt ssmpl-lock.json article.txt passwordB
```

### Tests

```bash
node js/test/test.js              # JS core (16 cases)
py -3.9 python/tests/test_ssmpl.py # Python (16 cases)
node js/test/interop.mjs          # JS <-> Python, GCM + CBC, both directions
```

> **Note on C++:** in this repo's dev environment a C++ compiler + OpenSSL weren't available, so
> `cpp/` is written to the standard OpenSSL API and ships with `CMakeLists.txt` + a self-test, but
> was **not compiled here**. It uses the exact same algorithms as JS/Python and interoperates.

### Honest boundaries ("what it is NOT")

- This is **access gating / strong encryption for a static site**, not a **per-user authorization
  system**. There are no accounts, no revocation, no per-user keys.
- The payload is public, so an attacker can **offline brute-force the password** by testing
  `K = P(password) XOR cipher-book` against the cipher's auth tag. Security = **password entropy ×
  KDF cost**. Use a strong password and a high iteration count.
- For fine-grained "user A sees this, user B sees that", you need a backend.

---

## License

MIT © 2026 LLYlab
