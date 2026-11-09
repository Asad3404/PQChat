"""Client entry point.

``python -m pqchat.client``             start the local web UI (default)
``python -m pqchat.client --selftest``  only check the post-quantum library
"""

import sys

if "--selftest" in sys.argv:
    from pqchat.selftest import main as selftest

    raise SystemExit(selftest())

from pqchat.client.app import main

main()
