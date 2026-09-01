# SSMPL — 静态站·多密码锁 / Static Site · Multi-Password Lock

A tiny, cross-language (Python / C++ / JavaScript) toolkit that lets a **fully static web site**
(no backend, no server) hide its content behind **one of several passwords**, using
**password-based key wrapping** — the "密本" (cipher book) scheme.

The whole point: **anyone can download the whole site (it is just static files), but without a
valid password the content is unreadable ciphertext.** The password is never stored, never sent
to a server, and treated as a **one-way** KDF; the content key is **two-way** (symmetric) so an
authorized reader can decrypt it back.

---

## The scheme (密本 / cipher-book)

Two layers, so re-keying is cheap:

1. **Content layer (two-way / symmetric).**
   Each piece of content is encrypted with a fresh random 256-bit key **K** using
   **AES-256-GCM** (authenticated) — or **AES-256-CBC + HMAC-SHA256** (encrypt-then-MAC).
   Because this is symmetric, K can decrypt it back: **reversible**.

2. **Key-wrapping layer (password → K).**
   A password never directly touches the content. Instead:
   - `P = PBKDF2-HMAC-hash(password, salt, iterations, 32)`  — a **one-way / salted / padded**
     KDF. `P` is the "encrypted password" (you can never get the password back from it).
   - **密本 (cipher book) = `P XOR K`** — the difference between the encrypted password and the
     content key. It is stored **publicly**.
   - To read: recompute `P` from the entered password, then `K = P XOR 密本`, then AES-decrypt.

Because the 密本 only wraps K (which is independent of the password), you can:

- **change a password** → recompute `密本 = P_new XOR K` (content is **not** re-encrypted);
- **add another password** → append a second 密本 for the same K (multi-password lock);
- keep the online payload **O(items)**, not O(users × items).

---

## Online payload format (the thing you host)

A single JSON blob (`ssmpl` version, config, items). Binary fields are **base64**.

```jsonc
{
  "ssmpl": 1,                       // format version
  "cipher": "AES-256-GCM",          // "AES-256-GCM" | "AES-256-CBC-HMAC-SHA256"
  "kdf": "PBKDF2-HMAC",
  "hash": "SHA-256",                // "SHA-256" | "SHA-512"
  "iterations": 250000,             // KDF cost (configurable)
  "salt": "<base64 16 bytes>",      // public salt (one per lock)
  "items": {
    "<name>": {
      "iv":   "<base64>",           // 12B (GCM) or 16B (CBC)
      "ct":   "<base64>",           // ciphertext
      "tag":  "<base64>",           // 16B GCM auth tag       (only for AES-256-GCM)
      "mac":  "<base64>",           // HMAC-SHA256 (32B)      (only for AES-256-CBC-HMAC-SHA256)
      "books": [ "<base64 密本>", ... ]   // one 密本 per authorized password
    }
  }
}
```

- `book = P XOR K` (32 bytes) for the password that produced `P`.
- A reader tries **each** 密本 in `books`: recompute `P` from the typed password, recover `K`,
  attempt decrypt; if it fails (wrong key), **try the next 密本**. If all fail → wrong password.

### Per-article, per-user access control (via 密本 presence)

Each item's `books` list is **independent per item**. Because a cipher-book only unlocks the one
item it was made for (it wraps that item's specific K), you can gate access **per article, per
user** purely by which cipher-books an article carries:

- **grant** a user an article → `add_password(item, user_password, admin_password, cfg)`
  (adds a 密本 = that user's P xor item's K to that item only);
- **deny** an article → don't add their cipher-book to that item (they cannot recover K);
- **revoke** an article → `remove_password(item, user_password, cfg)` (drops their cipher-book, no re-encrypt).

A single public JSON therefore expresses "user A reads X/Y, user B reads only Y, admin reads all".

Limits (by design of a static site): each user needs a distinct password; revocation removes the
cipher-book, not the ciphertext, so a user who already saved a cipher-book keeps reading; users can
share their password/cipher-book; the payload is public so weak passwords remain offline-attackable.

---

## API (the same ideas in all three languages)

Backend (encrypt / derive 密本 / multi-password) — Python, C++, JS:

| function | purpose |
|---|---|
| `derive_key(password, cfg)` | one-way: `P = KDF(password, salt, iterations, hash)` |
| `encrypt(plaintext, password, cfg)` | new random K, AES-encrypt, produce an **item** (one 密本) |
| `get_key(item, password, cfg)` | recover content key K by trying item's 密本s |
| `add_password(item, new_password, unlock_password, cfg)` | append a 密本 for `new_password`, **no re-encrypt** |
| `remove_password(item, password, cfg)` | drop `password`'s 密本 from one item — **revoke access, no re-encrypt** |
| `decrypt(item, password, cfg)` | two-way: recover plaintext |

Frontend (decrypt only, browser) — JS (WebCrypto):

| function | purpose |
|---|---|
| `unlock(password)` | validate a password against the blob; cache derived P |
| `decrypt(name)` | decrypt a named item using the unlocked P |

**Config** (settable, all three languages):

- `hash`  : `SHA-256` | `SHA-512`        — KDF hash
- `iterations` : integer                  — KDF cost
- `cipher` : `AES-256-GCM` | `AES-256-CBC-HMAC-SHA256`
- `salt`  : bytes                         — public salt (usually fixed for a lock)

> Security note: the online payload is public, so an attacker can **offline brute-force** the
> password by testing `K = P(password) XOR 密本` against the AES/GCM tag. Security therefore
> equals **password entropy + a high `iterations` cost**, not secrecy of the 密本. Use a strong
> password and a high iteration count; this is gating/obfuscation-grade protection for a static
> site, **not** per-user authorization (that needs a backend).
