# SSMPL — 静态站·多密码锁 / Static Site · Multi-Password Lock

<div align="center">

<a href="#中文"><kbd>中文</kbd></a>
&nbsp;&nbsp;·&nbsp;&nbsp;
<a href="#english"><kbd>English</kbd></a>

</div>

---

<a id="中文"></a>

## 中文

给**纯静态网站**（GitHub Pages 这类没有后端的托管）加“密码门禁”的小工具。核心就一句：整站可以被任何人下载，但**没有密码就读不出正文**；密码本身是**单向**的、不落盘、不上传；正文用的是**可逆**的对称加密，有授权就能看。

三套语言实现，同一套算法、互相能加解密：**JavaScript**（浏览器用 WebCrypto，Node 也能跑）· **Python** · **C++**（OpenSSL）。

### 它好在哪

- **纯静态就能跑。** 不需要服务器、不需要数据库，也就没有服务器要运维、没有后端可被黑。
- **是真加密，不是糊弄。** 正文用 AES-256-GCM（或 AES-256-CBC + HMAC），不是 base64，也不是写死一个密钥的异或。
- **多密码 / 换密码都不用重加密。** 文章用**随机密钥 K** 加密，密码只通过「密本」去包 K。所以加一个新密码或换密码，只要重算一遍密本 `P ⊕ K`，**文章密文一个字节都不用动**。
- **密码不会离开用户的浏览器。** 密码只在本地做单向派生（PBKDF2），不落盘、不上传，也就没有可被拖库的后端。
- **载荷很省。** 每篇只存一份密文，是 **O(篇数)**，不是 O(用户数 × 篇数)。换一次钥的成本就是一次异或。
- **关键参数都能调。** KDF 哈希（SHA-256/512）、迭代次数、加密方式（GCM / CBC+HMAC）都能改。

### 算法简说

```
存：  正文 --AES-256-GCM(随机密钥 K)--> 密文            （双向，能还原）
密码：密码 --PBKDF2-HMAC(盐, 迭代n)--> P (32字节)       （单向，拿不回密码）
密本：密本 = P ⊕ K   （“加密后的密码”与“密钥”的差，公开存）
读：  输入密码 -> P -> K = P ⊕ 密本 -> AES 解密
      如果这篇有多个密本（多密码），解密失败就试下一个
```

- 一篇正文只用一个随机 K 加密；密码只负责“包住”K。
- 加/换密码：给同一篇换个密码，再算一个新密本塞进 `books` 数组即可，正文不动。
- 所以密本依赖的只有密码的强弱和迭代次数，跟正文密文长度无关。

### 按文章、按用户给权限（这个才是重点）

每篇文章的 `books`（密本列表）是**彼此独立**的，同一个人在不同篇里可以有不同的密本或没有密本：

- **授权某人看某篇**：`add_password(那篇item, 那人的密码, 管理员密码, cfg)` —— 往这一篇塞一个该用户的密本。
- **不让某人看某篇**：那一篇的 `books` 里**不放**他的密本 —— 他算不出 K，读不了这篇。
- **收回某人的某篇**：`remove_password(那篇item, 那人的密码, cfg)` —— 只删这一篇里属于他的那条密本，正文不动。

所以一个公开的 JSON 就能做到「张三能看 A、B，李四只能看 B，管理员全看」：

```js
blob.items.A = await removePassword(await addPassword(itemA, 'zhang', 'admin', cfg), 'li', cfg);
blob.items.B = await removePassword(await addPassword(itemB, 'li',    'admin', cfg), 'zhang', cfg);
```

硬要挑刺的边界（照样写清楚）：

- 每个“用户”得用**不同的密码**（不然两个用户共用同一个密本，分不开）。
- 收回来的是**密本**，不是把密文改掉——所以重新托管 JSON 后，之前**已经拿到并保存的密本**的人仍能看（静态站没法“远程踢人”）。
- 用户之间可以转借密码/密本，静态站拦不住。
- 依然是**离线可穷举弱密码**，强口令 + 高迭代才是安全感来源。

### 在线载荷格式（托管到站点的那份 JSON）

```jsonc
{
  "ssmpl": 1,
  "cipher": "AES-256-GCM",            // 或 "AES-256-CBC-HMAC-SHA256"
  "kdf": "PBKDF2-HMAC",
  "hash": "SHA-256",                  // 或 "SHA-512"
  "iterations": 250000,
  "salt": "<base64>",
  "items": {
    "<名称>": { "iv": "...", "ct": "...", "tag": "..." 或 "mac": "...",
                "books": ["<base64 密本>", ...] }        // 一个密码对应一个密本
  }
}
```

### 配置（三个语言都能设）

| 字段 | 值 | 说明 |
|---|---|---|
| `hash` | `SHA-256` / `SHA-512` | 密码 KDF 的哈希 |
| `iterations` | 整数 | KDF 代价，越大越抗离线爆破 |
| `cipher` | `AES-256-GCM` / `AES-256-CBC-HMAC-SHA256` | 正文加密方式（推荐 GCM，带认证） |
| `salt` | bytes | 公开盐，一个 lock 固定一份 |

### 上手

**JavaScript**（`js/src/ssmpl.js`，浏览器 / Node ≥18 通用）

```js
import { Lock, encryptItem, addPassword, b64e } from './src/ssmpl.js';

// 后端：加密 + 再加一个密码
const salt = crypto.getRandomValues(new Uint8Array(16));
const cfg  = { hash:'SHA-256', iterations:250000, cipher:'AES-256-GCM', salt };
let item   = await encryptItem('正文…', '密码A', cfg);
item       = await addPassword(item, '密码B', '密码A', cfg);   // 不重加密

const blob = { ssmpl:1, cipher:cfg.cipher, kdf:'PBKDF2-HMAC', hash:cfg.hash,
               iterations:cfg.iterations, salt:b64e(salt), items:{ story:item } };

// 前端：使用者解锁并解密
const lock = new Lock(JSON.parse(JSON.stringify(blob)));
await lock.unlock('密码B');                 // 密码错则返回 false
const text = await lock.decrypt('story');
```

**Python**（`python/ssmpl/`）

```python
from ssmpl import Config, encrypt_item, add_password, Lock
cfg = Config(hash="SHA-256", iterations=250000, cipher="AES-256-GCM", salt=bytes(range(16)))
item = encrypt_item("正文…", "密码A", cfg)
item = add_password(item, "密码B", "密码A", cfg)
lock = Lock({"ssmpl":1,"cipher":cfg.cipher,"kdf":"PBKDF2-HMAC","hash":cfg.hash,
             "iterations":cfg.iterations,"salt":b64e(cfg.salt),"items":{"story":item}})
lock.unlock("密码B"); print(lock.decrypt("story"))
```

**C++**（`cpp/`，用 CMake 构建，需 OpenSSL）

```bash
cd cpp && cmake -B build && cmake --build build
./build/test_ssmpl        # 自测：往返 + 多密码 + GCM/CBC
./build/ssmpl_cli encrypt 密码A article.txt
./build/ssmpl_cli addpass ssmpl-lock.json article.txt 密码B 密码A
./build/ssmpl_cli decrypt ssmpl-lock.json article.txt 密码B
```

### 测试

```bash
node js/test/test.js                # JS 16 用例
py -3.9 python/tests/test_ssmpl.py  # Python 16 用例
node js/test/interop.mjs            # JS <-> Python 互通（GCM/CBC 双向）
```

> 环境里没装 C++ 编译器和 OpenSSL，所以 `cpp/` 是按标准 OpenSSL 写的、带了构建文件和自测，但**没有在本机编译运行**。算法和 JS/Python 一致，装好后 `cmake --build` 就能跑。

### 别过度期待的地方

这是**静态站的访问门禁 + 口令级权限**：能用「这篇的 `books` 里有没有某人的密本」做到按文章、按用户给权限（见上一节）。但它**不是服务器式账号系统**——没有登录态，不能“远程踢掉”已经拿到密本的人，也拦不住用户把密码/密本转借他人。载荷公开意味着弱密码可被**离线穷举**，安全感 = 密码强度 × 迭代次数。要真正的账户鉴权 + 服务器端吊销，那得用后端。

详见 [docs/SPEC.md](docs/SPEC.md)。

---

<a id="english"></a>

## English

A small toolkit that adds **password gates to a fully static site** (GitHub Pages and similar — no backend). The gist: anyone can download the whole site, but **without a valid password the content is unreadable**. The password is **one-way**, never stored, never uploaded; the content uses **reversible** symmetric encryption, so an authorized reader gets it back.

Three implementations of the same, interoperable spec: **JavaScript** (WebCrypto in browsers, also Node) · **Python** · **C++** (OpenSSL).

### What it gets you

- **Runs on static hosting.** No server, no database — nothing to operate, nothing on the server side to breach.
- **Real crypto, not obfuscation.** AES-256-GCM (or AES-256-CBC + HMAC) for the content — not base64, not a hard-coded XOR key.
- **Add or change a password without re-encrypting.** Content is encrypted with a **random key K**; passwords only wrap K via the **cipher-book** (密本). Add a password or change one by recomputing `cipher-book = P ⊕ K` — the **ciphertext doesn't change at all**.
- **The password never leaves the browser.** It's only hashed locally (PBKDF2), nothing is stored or transmitted, so there's no backend to leak from.
- **Cheap payload.** One ciphertext per item → **O(items)**, not O(users × items). A re-key costs one XOR.
- **Configurable.** KDF hash (SHA-256/512), iteration count, and cipher (GCM / CBC+HMAC) are all settable.

### Algorithm, briefly

```
store:   plaintext --AES-256-GCM(random key K)--> ciphertext     (two-way, reversible)
password: password --PBKDF2-HMAC(salt, iters)--> P (32 bytes)    (one-way, irreversible)
book:    cipher-book = P ⊕ K   (difference of the hashed password and the content key)

read:    type password -> P -> K = P ⊕ cipher-book -> AES decrypt
         if the item has several books (multi-password), a failed key tries the next
```

- One random K encrypts each piece of content; a password only "wraps" K.
- Add/change a password: recompute a new `cipher-book` for the same K and push it into `books` — the content stays untouched.
- Security therefore depends on password strength and KDF cost, not on the ciphertext length.

### Per-article, per-user access control (the real point)

Each item's `books` (cipher-books) is **independent** — the same person can have a 密本 in one article and no 密本 in another.

- **Grant a user an article**: `add_password(thatItem, thatUserPassword, adminPassword, cfg)` — put one of that user's cipher-books into that article.
- **Deny a user an article**: just **don't put their cipher-book** in that article's `books` — they can't recover K, so they can't read it.
- **Revoke a user's article**: `remove_password(thatItem, thatUserPassword, cfg)` — drop only their cipher-book from that item; the content stays untouched.

So one public JSON can express "张三 reads A/B, 李四 reads only B, admin reads all":

```js
blob.items.A = await removePassword(await addPassword(itemA, 'zhang', 'admin', cfg), 'li', cfg);
blob.items.B = await removePassword(await addPassword(itemB, 'li',    'admin', cfg), 'zhang', cfg);
```

Honest limits, stated plainly:

- Each "user" needs a **distinct password** (otherwise two users share the same cipher-book and can't be told apart).
- You revoke the **cipher-book**, not the ciphertext — so anyone who already downloaded a cipher-book keeps reading; a static site can't "kick" someone remotely.
- Users can hand their password / cipher-book to someone else; a static site can't stop it.
- Weak passwords are still **offline-attackable**; a strong password + high iteration count is what buys real safety.

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
    "<name>": { "iv": "…", "ct": "…", "tag": "…" or "mac": "…",
                "books": ["<base64 cipher-book>", …] }   // one per authorized password
  }
}
```

### Config (each language)

| field | values | notes |
|---|---|---|
| `hash` | `SHA-256` / `SHA-512` | one-way password KDF hash |
| `iterations` | integer | KDF cost; higher = slower offline brute-force |
| `cipher` | `AES-256-GCM` / `AES-256-CBC-HMAC-SHA256` | content cipher (GCM is authenticated, recommended) |
| `salt` | bytes | public salt, fixed per lock |

### Quickstart

**JavaScript** (`js/src/ssmpl.js`, browser / Node ≥18)

```js
import { Lock, encryptItem, addPassword, b64e } from './src/ssmpl.js';

const salt = crypto.getRandomValues(new Uint8Array(16));
const cfg  = { hash:'SHA-256', iterations:250000, cipher:'AES-256-GCM', salt };
let item   = await encryptItem('body…', 'passwordA', cfg);
item       = await addPassword(item, 'passwordB', 'passwordA', cfg);   // no re-encryption

const blob = { ssmpl:1, cipher:cfg.cipher, kdf:'PBKDF2-HMAC', hash:cfg.hash,
               iterations:cfg.iterations, salt:b64e(salt), items:{ story:item } };

const lock = new Lock(JSON.parse(JSON.stringify(blob)));
await lock.unlock('passwordB');               // false if wrong
const text = await lock.decrypt('story');
```

**Python** (`python/ssmpl/`)

```python
from ssmpl import Config, encrypt_item, add_password, Lock
cfg = Config(hash="SHA-256", iterations=250000, cipher="AES-256-GCM", salt=bytes(range(16)))
item = encrypt_item("body…", "passwordA", cfg)
item = add_password(item, "passwordB", "passwordA", cfg)
lock = Lock({"ssmpl":1,"cipher":cfg.cipher,"kdf":"PBKDF2-HMAC","hash":cfg.hash,
             "iterations":cfg.iterations,"salt":b64e(cfg.salt),"items":{"story":item}})
lock.unlock("passwordB"); print(lock.decrypt("story"))
```

**C++** (`cpp/`, CMake + OpenSSL)

```bash
cd cpp && cmake -B build && cmake --build build
./build/test_ssmpl        # round-trip + multi-password + GCM/CBC
./build/ssmpl_cli encrypt passwordA article.txt
./build/ssmpl_cli addpass ssmpl-lock.json article.txt passwordB passwordA
./build/ssmpl_cli decrypt ssmpl-lock.json article.txt passwordB
```

### Tests

```bash
node js/test/test.js              # JS 16 cases
py -3.9 python/tests/test_ssmpl.py  # Python 16 cases
node js/test/interop.mjs          # JS <-> Python, GCM + CBC, both directions
```

> This environment has no C++ compiler or OpenSSL, so `cpp/` is written against the standard OpenSSL
> API with build files and a self-test, but was **not compiled here**. It uses the same algorithms
> as JS/Python and interoperates.

### Don't over-expect

This is **access gating + password-level permissions** on a static site: you can grant/deny
per-article, per-user by whether that article's `books` contains a user's cipher-book (see above).
It is **not a server-style account system** — no session, no way to remotely revoke someone who
already holds a cipher-book, and no way to stop people sharing passwords / cipher-books. The
payload is public, so weak passwords are **offline-attackable**; safety = password strength × KDF
cost. For real account auth + server-side revocation you'd need a backend.

See [docs/SPEC.md](docs/SPEC.md).

---

## License

MIT © 2026 LLYlab
