# -*- coding: utf-8 -*-
"""SSMPL Python self-test. Run: py -3.9 python/tests/test_ssmpl.py"""
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ssmpl import Config, encrypt_item, decrypt_item, add_password, get_key, Lock, b64e, b64d

SALT = bytes(range(16))
pass_n = fail_n = 0
def check(name, cond):
    global pass_n, fail_n
    if cond: pass_n += 1; print("  ok  " + name)
    else: fail_n += 1; print("FAIL  " + name)

def endswith_wrong(item, pw, cfg):
    try:
        decrypt_item(item, pw, cfg); return False
    except Exception:
        return True

GCM   = Config(hash="SHA-256", iterations=1000, cipher="AES-256-GCM", salt=SALT)
SHA512= Config(hash="SHA-512", iterations=1500, cipher="AES-256-GCM", salt=SALT)
CBC   = Config(hash="SHA-256", iterations=1000, cipher="AES-256-CBC-HMAC-SHA256", salt=SALT)

print("# encrypt/decrypt (GCM)")
item = encrypt_item("黄文正文·第一章 secret content", "alpha", GCM)
check("decrypt correct pw", decrypt_item(item, "alpha", GCM) == "黄文正文·第一章 secret content")
check("wrong pw rejected", endswith_wrong(item, "nope", GCM))

print("# multi-password (密本, no re-encrypt)")
item2 = add_password(item, "beta", "alpha", GCM)
check("alpha still works", decrypt_item(item2, "alpha", GCM) == "黄文正文·第一章 secret content")
check("beta added works", decrypt_item(item2, "beta", GCM) == "黄文正文·第一章 secret content")
check("no re-encryption (ct/iv unchanged, books grew)", item2["ct"] == item["ct"] and item2["iv"] == item["iv"] and len(item2["books"]) == 2)

print("# config (SHA-512)")
ia = encrypt_item("你好 world 123", "p1", SHA512)
check("SHA-512 round-trips", decrypt_item(ia, "p1", SHA512) == "你好 world 123")
check("SHA-512 wrong pw rejected", endswith_wrong(ia, "zzz", SHA512))

print("# CBC + HMAC (encrypt-then-MAC)")
ic = encrypt_item("cbc data 数据", "cbc1", CBC)
check("CBC round-trips", decrypt_item(ic, "cbc1", CBC) == "cbc data 数据")
check("CBC wrong pw rejected", endswith_wrong(ic, "x", CBC))

print("# frontend Lock (blob JSON)")
blob = {"ssmpl":1,"cipher":"AES-256-GCM","kdf":"PBKDF2-HMAC","hash":"SHA-256","iterations":1000,"salt":b64e(SALT),"items":{"story":item,"cbc":ic}}
lock = Lock(json.loads(json.dumps(blob)))
check("not unlocked initially", not lock.is_unlocked())
check("wrong pw unlock fails", lock.unlock("zzz") is False)
check("correct pw unlock (alpha)", lock.unlock("alpha") is True)
check("decrypt story", lock.decrypt("story") == "黄文正文·第一章 secret content")

lock_cbc = Lock(json.loads(json.dumps({**blob, "cipher":"AES-256-CBC-HMAC-SHA256", "items":{"c":ic}})))
check("CBC Lock unlock", lock_cbc.unlock("cbc1") is True)
check("CBC Lock decrypt", lock_cbc.decrypt("c") == "cbc data 数据")

print("# setters (chainable)")
check("set_* chainable", isinstance(Config().set_hash("SHA-256"), Config))

print("\n== %d passed, %d failed ==" % (pass_n, fail_n))
sys.exit(1 if fail_n else 0)
