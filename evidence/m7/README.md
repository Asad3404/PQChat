# M7 evidence: packet captures

| File | What | How |
|---|---|---|
| `tls-session.pcap` | Docker Compose relay, TLS 1.3, two browsers chatting (M6 E2E run) | `tcpdump -i br-<pqnet> "tcp port 8000"` during `scripts/e2e_browser.mjs` |
| `no-tls-e2e-only.pcap` | In-process relay **without TLS**, to show what the E2E layer alone protects | `tcpdump -i lo tcp` during `tests/integration/test_clients.py::test_chat_persistence_and_restart` |

Analysis and results: `docs/notes/m7-network.md` §2. Reproduce the checks:

    tshark -r tls-session.pcap -Y "tls.handshake.type == 2" -T fields \
        -e tls.handshake.extensions.supported_version -e tls.handshake.ciphersuite \
        -e tls.handshake.extensions_key_share_group
    grep -c -a -F "Hi Bob" tls-session.pcap          # 0
    grep -c -a -F '"from":"alice"' no-tls-e2e-only.pcap   # 2: sender metadata without TLS

All accounts and messages are synthetic (PROJECT-BRIEF.md §10).
