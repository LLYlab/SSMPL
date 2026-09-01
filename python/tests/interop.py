# -*- coding: utf-8 -*-
"""Cross-language interop: generate Python fixtures, verify JS fixtures (mirror of js/test/interop.mjs)."""
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ssmpl import Config, encrypt_item, decrypt_item

HERE = os.path.dirname(__file__)
DIR = os.path.join(HERE, "..", "..", "test-interop")
os.makedirs(DIR, exist_ok=True)

SALT = bytes(range(16))
PW = "interop-pw"
PLAIN = "跨语言互通测试 SSMPL interop"
GCM = Config(hash="SHA-256", iterations=1000, cipher="AES-256-GCM", salt=SALT)
CBC = Config(hash="SHA-256", iterations=1000, cipher="AES-256-CBC-HMAC-SHA256", salt=SALT)

def w(name, obj):
    with open(os.path.join(DIR, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

# generate Python fixtures
w("py_gcm.json", encrypt_item(PLAIN, PW, GCM))
w("py_cbc.json", encrypt_item(PLAIN, PW, CBC))
print("wrote py_gcm.json / py_cbc.json")

# verify JS fixtures (other direction)
for name, cfg in (("js_gcm.json", GCM), ("js_cbc.json", CBC)):
    p = os.path.join(DIR, name)
    if not os.path.exists(p):
        print("  -    JS fixture %s not present, skipping" % name)
        continue
    with open(p, encoding="utf-8") as f:
        item = json.load(f)
    ok = decrypt_item(item, PW, cfg) == PLAIN
    print("  ok  JS->Python %s decrypt" % name if ok else "FAIL  JS->Python %s" % name)
