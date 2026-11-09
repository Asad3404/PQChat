# Rule tests for pqchat-rules.yml, run with: semgrep --test .semgrep
# Each "ruleid:" line must be flagged; each "ok:" line must not.
# This file is never imported; it exists only to prove the rules fire.
# ruleid: pqchat-no-random-module
import random
# ruleid: pqchat-no-unsafe-deserialisation
import pickle
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def check(tag, expected_tag, mac, data, key, iv, a, b):
    # ruleid: pqchat-non-constant-time-compare
    if tag == expected_tag:
        pass
    # ruleid: pqchat-non-constant-time-compare
    if mac != data:
        pass
    # ok: pqchat-non-constant-time-compare
    if a == b:
        pass
    # ok: pqchat-non-constant-time-compare
    if len(key) != 32:
        pass
    # ruleid: pqchat-non-constant-time-compare
    if key == iv:
        pass
    # ruleid: pqchat-no-eval-exec
    eval("1")
    # ruleid: pqchat-no-hazmat-primitive-construction
    Cipher(algorithms.AES(key), modes.CBC(iv))
    # ok: pqchat-non-constant-time-compare
    return hmac.compare_digest(tag, expected_tag)
