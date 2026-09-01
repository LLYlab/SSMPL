# -*- coding: utf-8 -*-
"""SSMPL — Static Site · Multi-Password Lock.  Python / pycryptodome.

Backend (encrypt / 密本 / multi-password) mirror of the JS module.
The hosted payload is a JSON blob; a reader needs a valid password to recover plaintext.

Config fields (settable via Config or a dict):
    hash       : "SHA-256" | "SHA-512"
    iterations : int (KDF cost)
    cipher     : "AES-256-GCM" | "AES-256-CBC-HMAC-SHA256"
    salt       : bytes (>= 8, public)
"""
import base64, hashlib, hmac, json, os

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
except Exception as e:  # pragma: no cover
    raise ImportError("SSMPL python needs pycryptodome: pip install pycryptodome") from e


class Config:
    def __init__(self, hash="SHA-256", iterations=250000, cipher="AES-256-GCM", salt=None):
        self.hash = hash
        self.iterations = iterations
        self.cipher = cipher
        self.salt = salt
    def set_hash(self, h):  self.hash = h;  return self
    def set_iterations(self, n): self.iterations = n; return self
    def set_cipher(self, c): self.cipher = c; return self
    def set_salt(self, s): self.salt = s; return self

    def _norm(self):
        if not self.salt or len(self.salt) < 8:
            raise ValueError("SSMPL: salt must be set (>=8 bytes).")
        if self.hash.upper() not in ("SHA-256", "SHA-512"):
            raise ValueError("SSMPL: hash must be SHA-256 or SHA-512")
        if self.cipher not in ("AES-256-GCM", "AES-256-CBC-HMAC-SHA256"):
            raise ValueError("SSMPL: unsupported cipher %r" % self.cipher)
        return self


# ---------- bytes / base64 ----------
def b64e(b): return base64.b64encode(b).decode("ascii")
def b64d(s): return base64.b64decode(s)
def xor_bytes(a, b): return bytes(x ^ y for x, y in zip(a, b))


# ---------- one-way KDF: P = PBKDF2(password, salt, iterations, 32) ----------
def derive_key(password, cfg):
    c = norm(cfg)
    return hashlib.pbkdf2_hmac(
        c.hash.lower().replace("-", ""),      # sha256 / sha512
        str(password).encode("utf-8"), c.salt, int(c.iterations), dklen=32)


# ---------- two-way symmetric cipher, + integrity ----------
def _mac_key(K):
    return hashlib.sha256(K + b"SSMPL.HMAC").digest()

def encrypt_bytes(plain, K, cfg):
    c = norm(cfg)
    data = plain.encode("utf-8") if isinstance(plain, str) else plain
    if c.cipher == "AES-256-CBC-HMAC-SHA256":
        iv = os.urandom(16)
        ct = AES.new(K, AES.MODE_CBC, iv=iv).encrypt(pad(data, 16))
        mac = hmac.new(_mac_key(K), iv + ct, hashlib.sha256).digest()
        return {"iv": b64e(iv), "ct": b64e(ct), "mac": b64e(mac)}
    else:  # AES-256-GCM
        iv = os.urandom(12)
        ct, tag = AES.new(K, AES.MODE_GCM, nonce=iv).encrypt_and_digest(data)
        return {"iv": b64e(iv), "ct": b64e(ct), "tag": b64e(tag)}

def decrypt_bytes(item, K, cfg):
    c = norm(cfg)
    if c.cipher == "AES-256-CBC-HMAC-SHA256":
        mac = hmac.new(_mac_key(K), b64d(item["iv"]) + b64d(item["ct"]), hashlib.sha256).digest()
        if not hmac.compare_digest(mac, b64d(item["mac"])):
            raise ValueError("SSMPL: MAC mismatch (wrong key).")
        pt = AES.new(K, AES.MODE_CBC, iv=b64d(item["iv"])).decrypt(b64d(item["ct"]))
        return unpad(pt, 16).decode("utf-8")
    else:  # AES-256-GCM
        pt = AES.new(K, AES.MODE_GCM, nonce=b64d(item["iv"])).decrypt_and_verify(b64d(item["ct"]), b64d(item["tag"]))
        return pt.decode("utf-8")


# ---------- 密本 = P XOR K ----------
def compute_book(P, K): return xor_bytes(P, K)


# ---------- backend operations ----------
def _unlock_key(item, P, cfg):
    for bk in item["books"]:
        K = xor_bytes(P, b64d(bk))
        try:
            decrypt_bytes(item, K, cfg)
            return K
        except Exception:
            continue
    return None

def encrypt_item(plaintext, password, cfg):
    c = norm(cfg)
    K = os.urandom(32)
    item = encrypt_bytes(plaintext, K, c)
    P = derive_key(password, c)
    item = dict(item)
    item["books"] = [b64e(compute_book(P, K))]
    return item

def get_key(item, password, cfg):
    c = norm(cfg)
    P = derive_key(password, c)
    return _unlock_key(item, P, c)

def decrypt_item(item, password, cfg):
    K = get_key(item, password, cfg)
    if K is None:
        raise ValueError("SSMPL: wrong password (no 密本 decrypts).")
    return decrypt_bytes(item, K, cfg)

def add_password(item, new_password, unlock_password, cfg):
    K = get_key(item, unlock_password, cfg)
    if K is None:
        raise ValueError("SSMPL: unlock_password is wrong.")
    P = derive_key(new_password, cfg)
    item = dict(item)
    item["books"] = list(item.get("books", [])) + [b64e(compute_book(P, K))]
    return item

def remove_password(item, password, cfg):
    """Drop a password's 密本 from ONE item (revoke access). No re-encryption."""
    c = norm(cfg)
    P = derive_key(password, c)
    keep = []
    for bk in item.get("books", []):
        K = xor_bytes(P, b64d(bk))
        try:
            decrypt_bytes(item, K, c)      # this book matches the password -> it's theirs -> drop
            continue
        except Exception:
            keep.append(bk)
    item = dict(item)
    item["books"] = keep
    return item


# ---------- helpers ----------
def norm(cfg):
    if isinstance(cfg, Config):
        return cfg._norm()
    c = Config(**{k: cfg[k] for k in ("hash", "iterations", "cipher", "salt") if k in cfg})
    return c._norm()


# ---------- frontend lock ----------
class Lock:
    def __init__(self, blob, cfg=None):
        self.blob = blob
        self.config = Config(
            hash=(cfg or {}).get("hash", "SHA-256"),
            iterations=(cfg or {}).get("iterations", 250000),
            cipher=(cfg or {}).get("cipher", "AES-256-GCM"),
            salt=b64d(blob["salt"]) if blob.get("salt") else None,
        )
        # blob is authoritative; only explicit cfg overrides win
        self.config.hash = (cfg or {}).get("hash", blob.get("hash", "SHA-256"))
        self.config.iterations = (cfg or {}).get("iterations", blob.get("iterations", 250000))
        self.config.cipher = (cfg or {}).get("cipher", blob.get("cipher", "AES-256-GCM"))
        self.config.salt = b64d(blob["salt"]) if blob.get("salt") else (cfg or {}).get("salt")
        self._P = None
        self._cfg = None

    def set_config(self, cfg=None, **kw):
        for k, v in (cfg or {}).items():
            setattr(self.config, k, v)
        for k, v in kw.items():
            setattr(self.config, k, v)
        self._P = None
        return self

    def is_unlocked(self): return self._P is not None

    def unlock(self, password):
        c = self.config
        P = derive_key(password, c)
        for name, item in self.blob.get("items", {}).items():
            K = _unlock_key(item, P, c)
            if K:
                self._P = P
                self._cfg = c
                return True
        return False

    def unlock_key(self, password):
        """Backend-style helper: return the derived P if the password unlocks."""
        return self._P if self._P else (self.unlock(password) and self._P)

    def decrypt(self, name):
        if self._P is None:
            raise ValueError("SSMPL: not unlocked yet.")
        item = self.blob["items"][name]
        K = _unlock_key(item, self._P, self._cfg)
        if K is None:
            raise ValueError("SSMPL: cannot decrypt item (wrong key).")
        return decrypt_bytes(item, K, self._cfg)
