# -*- coding: utf-8 -*-
"""SSMPL — Static Site · Multi-Password Lock (Python)."""
from .core import (
    Config, b64e, b64d, xor_bytes, derive_key, encrypt_bytes, decrypt_bytes,
    compute_book, encrypt_item, get_key, decrypt_item, add_password, remove_password, Lock,
)
__all__ = [
    "Config", "b64e", "b64d", "xor_bytes", "derive_key", "encrypt_bytes",
    "decrypt_bytes", "compute_book", "encrypt_item", "get_key", "decrypt_item",
    "add_password", "remove_password", "Lock",
]
__version__ = "1.0.0"
