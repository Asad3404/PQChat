#!/usr/bin/env bash
# Print what the running relay stores (used for the demo video's "relay" card).
#   scripts/relay_view.sh > demo-out/relay_view.txt
# Read-only: opens the database with mode=ro inside the relay container. Pass the texts you sent
# in the demo as arguments to show they are absent from the database file.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose exec -T relay python - "$@" <<'PY'
import sqlite3, sys
db = sqlite3.connect("file:/data/relay.db?mode=ro", uri=True)
print("$ sqlite3 /data/relay.db   (relay operator's view)")
print("> SELECT username, length(identity) FROM accounts;")
for name, n in db.execute("SELECT username, length(identity) FROM accounts"):
    print(f"  {name:<6} | {n} bytes of PUBLIC keys + signatures")
print("> SELECT alg, count(*) FROM one_time_prekeys GROUP BY alg;   -- both users")
for alg, n in db.execute("SELECT CASE alg WHEN 1 THEN 'X25519' ELSE 'ML-KEM-768' END, count(*) FROM one_time_prekeys GROUP BY alg"):
    print(f"  {alg:<10} | {n} public one-time prekeys left")
print("> SELECT count(*) FROM queue;   -- messages waiting for delivery")
print("  " + str(db.execute("SELECT count(*) FROM queue").fetchone()[0]) + "   (delivered messages are deleted)")
raw = open("/data/relay.db", "rb").read()
for marker in sys.argv[1:]:
    print(f"$ grep -c '{marker}' relay.db  ->  {raw.count(marker.encode())}")
PY
