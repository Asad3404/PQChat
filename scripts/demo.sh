#!/usr/bin/env bash
# PQ-Chat demo (Milestone 12). Starts the relay and two clients and prints the two browser links.
#
#   scripts/demo.sh            start the stack and print the links
#   scripts/demo.sh --e2e      also drive both browsers automatically (needs Node + Playwright)
#   scripts/demo.sh --down     stop the stack and delete its volumes (demo data only)
#   add --no-build to reuse images that are already built
set -euo pipefail
cd "$(dirname "$0")/.."
BUILD=1; E2E=0
for arg in "$@"; do
  case "$arg" in
    --no-build) BUILD=0 ;;
    --e2e) E2E=1 ;;
  esac
done

if [[ "${1:-}" == "--down" ]]; then
  docker compose down -v
  exit 0
fi

if [[ $BUILD == 1 ]]; then
  echo "==> Building images (compiles liboqs 0.16.0 from source the first time; a few minutes)"
  docker compose build
fi
echo "==> Starting relay (TLS 1.3) and two clients"
docker compose up -d --no-build
for _ in $(seq 1 60); do
  [[ "$(docker inspect -f '{{.State.Health.Status}}' pqchat-relay-1 2>/dev/null)" == healthy ]] && break
  sleep 2
done
sleep 3
link() { docker compose logs "$1" 2>&1 | grep -o "http://127.0.0.1:[0-9]*/#token=[A-Za-z0-9_-]*" | tail -1; }
ALICE=$(link alice)
BOB=$(link bob)
cat <<MSG

PQ-Chat is running.

  Alice:  $ALICE
  Bob:    $BOB

Open each link in its own browser window (or a private window for one of them).
1. Create an identity: username "alice" / "bob", passphrase of at least 10 characters.
2. As alice, press "+" and start a chat with "bob". Send a message.
3. As bob, open the chat and reply. Open the (i) panel on both sides: the 60-digit
   safety numbers must match. Mark them as verified.

Stop and delete the demo data with:  scripts/demo.sh --down
MSG

if [[ $E2E == 1 ]]; then
  echo "==> Driving both browsers automatically"
  NODE_PATH="${NODE_PATH:-$(npm root -g)}" node scripts/e2e_browser.mjs "$ALICE" "$BOB" evidence/m6
fi
