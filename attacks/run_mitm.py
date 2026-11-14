"""Run the MITM prekey-swap attacks end to end and write evidence/m8/mitm-results.json.

    python attacks/run_mitm.py [--mitmdump /opt/attack-venv/bin/mitmdump]

Topology (all on 127.0.0.1, synthetic users):  Alice --ws--> mitmdump (attacker) --ws--> relay <--ws-- Bob
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from tests.relay_harness import running_relay  # noqa: E402

from pqchat.client.core import ChatClient, KeyChangedError  # noqa: E402
from pqchat.protocol.errors import DowngradeError, ProtocolError, VerificationError  # noqa: E402

PASS = "synthetic attack passphrase"  # noqa: S105 - synthetic test account


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


async def wait_for(pred, timeout: float = 10.0) -> bool:  # type: ignore[no-untyped-def]
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        await asyncio.sleep(0.05)
    return False


async def scenario(
    mode: str, relay_addr: str, proxy_port: int, workdir: Path, pin_first: bool
) -> dict:  # type: ignore[type-arg]
    bob = ChatClient(workdir / "bob", f"ws://{relay_addr}/ws")
    bob.unlock("bob", PASS)
    await bob.connect()
    direct = ChatClient(workdir / "alice", f"ws://{relay_addr}/ws")
    direct.unlock("alice", PASS)
    await direct.connect()
    if pin_first:  # earlier, untampered contact: alice pins bob's real identity
        await direct.send_text("bob", "hello before the attack")
        await wait_for(lambda: bool(bob.state and bob.state.history.get("alice")))
        direct.state.sessions.pop("bob", None)  # type: ignore[union-attr]  # force a new handshake
        direct.save()
    await direct.close()
    alice = ChatClient(workdir / "alice", f"ws://127.0.0.1:{proxy_port}/ws")  # via attacker
    alice.unlock("alice", PASS)
    await alice.connect()
    outcome: dict[str, object] = {"mode": mode, "pinned_before": pin_first}
    try:
        await alice.send_text("bob", "secret plan for thursday")
        outcome["alice_sent"] = True
    except KeyChangedError:
        outcome["alice_sent"] = False
        outcome["blocked_by"] = "KeyChangedError (identity pinned, SR-17)"
    except DowngradeError:
        outcome["alice_sent"] = False
        outcome["blocked_by"] = "DowngradeError (no post-quantum prekey, SR-6)"
    except VerificationError as e:
        outcome["alice_sent"] = False
        outcome["blocked_by"] = f"VerificationError ({e})"
    except ProtocolError as e:
        outcome["alice_sent"] = False
        outcome["blocked_by"] = f"{type(e).__name__} ({e})"
    await asyncio.sleep(1.0)
    received = [
        m["text"]
        for m in (bob.state.history.get("alice", []) if bob.state else [])
        if m["dir"] == "in"
    ]
    outcome["bob_received"] = received
    outcome["safety_number_alice_sees_for_bob"] = "".join(alice.safety_number("bob") or [])
    outcome["safety_number_bob_sees_for_alice"] = "".join(bob.safety_number("alice") or [])
    outcome["safety_numbers_match"] = outcome["safety_number_alice_sees_for_bob"] == outcome[
        "safety_number_bob_sees_for_alice"
    ] and bool(outcome["safety_number_bob_sees_for_alice"])
    await alice.close()
    await bob.close()
    return outcome


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mitmdump", default="/opt/attack-venv/bin/mitmdump")
    ap.add_argument("--out", default=str(ROOT / "evidence" / "m8" / "mitm-results.json"))
    args = ap.parse_args()
    results = []
    for mode, pin_first in [
        ("swap-spk", False),
        ("strip-pq", False),
        ("swap-identity", False),
        ("swap-identity", True),
    ]:
        with tempfile.TemporaryDirectory() as tmp, running_relay() as (relay_addr, _):
            work = Path(tmp)
            log = work / "attack.jsonl"
            port = free_port()
            env = {**os.environ, "PQCHAT_ATTACK": mode, "PQCHAT_ATTACK_LOG": str(log)}
            cmd = [
                args.mitmdump,
                "--mode",
                f"reverse:http://{relay_addr}",
                "--listen-host",
                "127.0.0.1",
                "--listen-port",
                str(port),
                "-q",
                "-s",
                str(ROOT / "attacks" / "mitm_prekey_swap.py"),
            ]
            # The mitmdump path is the operator's own CLI argument; arguments are a list (no shell).
            proc = subprocess.Popen(cmd, env=env)  # noqa: S603  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
            try:
                time.sleep(4)
                outcome = asyncio.run(scenario(mode, relay_addr, port, work, pin_first))
            finally:
                proc.terminate()
                proc.wait(10)
            outcome["attacker_log"] = (
                [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
            )
            results.append(outcome)
            print(
                json.dumps({k: v for k, v in outcome.items() if not k.startswith("safety_number_")})
            )
    Path(args.out).write_text(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
