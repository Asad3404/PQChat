# Attack suite (Milestone 8)

Attack only this system, locally or in the Compose network, with synthetic accounts (CLAUDE.md §10).
Results and CVSS scores: `docs/pentest-report.md`. Evidence: `evidence/m8/`.

Attack tools live in their own virtualenv so they never mix with PQ-Chat's pinned dependencies:

    python3.12 -m venv .attack-venv
    .attack-venv/bin/pip install mitmproxy cvss
    .attack-venv/bin/pip install -c requirements/constraints.txt liboqs-python argon2-cffi

| Script | Attack | Threat |
|---|---|---|
| `run_mitm.py` + `mitm_prekey_swap.py` | mitmproxy rewrites prekey bundles: swap prekey, strip ML-KEM, swap identity (first contact / pinned) | T-01, T-02, T-04 |
| `replay.py` | malicious relay re-delivers a handshake and a ratchet message | T-06, T-07 |
| `downgrade.py` | relay strips KEM prekeys; attacker rewrites the mode byte | T-04 |
| `fuzz_parsers.py` | Hypothesis fuzzing of every parser (random + mutated valid inputs) | T-10 |
| `key_compromise_demo.py` | device theft at time t, classical vs. quantum attacker | T-24, T-25 |

    .venv/bin/python attacks/run_mitm.py --mitmdump .attack-venv/bin/mitmdump
    .venv/bin/python attacks/replay.py
    .venv/bin/python attacks/downgrade.py
    .venv/bin/python attacks/key_compromise_demo.py
    .venv/bin/python attacks/fuzz_parsers.py --examples 20000

OWASP ZAP (with `docker compose up -d` running; TOKEN = the value after `#token=` in
`docker compose logs alice`):

    Z="-config replacer.full_list(0).description=token -config replacer.full_list(0).enabled=true \
       -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=X-PQChat-Token \
       -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=$TOKEN"
    docker run --rm --network host -v "$PWD/evidence/m8/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
        zap-baseline.py -t http://127.0.0.1:8701/ -r baseline.html -J baseline.json -z "$Z"
    docker run --rm --network host -v "$PWD/evidence/m8/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
        zap-api-scan.py -t /zap/wrk/ui-openapi.yaml -f openapi -r api-scan.html -J api-scan.json -z "$Z"
