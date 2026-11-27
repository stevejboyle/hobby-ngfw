#!/usr/bin/env python3
"""Test harness only: stands in for `journalctl -f -o json` in the log
forwarding gate (lab containers have no journal). It follows the JSON lines
in $LOGFWD_FEED, honouring -n 0 (from now on) and --after-cursor C (after
the record whose __CURSOR is C), and ignores the match arguments. Without
-f (the Logs views) it prints the whole feed once; the readers skip what
isn't theirs."""
import json, os, sys, time

feed = os.environ.get("LOGFWD_FEED")
if not feed:
    sys.exit(0)
if "-f" not in sys.argv:
    if os.path.exists(feed):
        sys.stdout.write(open(feed).read())
    sys.exit(0)
args = sys.argv[1:]
after = args[args.index("--after-cursor") + 1] if "--after-cursor" in args else None
open(feed, "a").close()
with open(feed) as f:
    lines = f.readlines()
    if after is not None:
        idx = next((i for i, l in enumerate(lines) if json.loads(l).get("__CURSOR") == after), None)
        if idx is None:
            sys.stderr.write("Failed to seek to cursor\n")
            sys.exit(1)
        for l in lines[idx + 1:]:
            sys.stdout.write(l)
        sys.stdout.flush()
    while True:
        l = f.readline()
        if not l:
            time.sleep(0.1)
            continue
        sys.stdout.write(l)
        sys.stdout.flush()
