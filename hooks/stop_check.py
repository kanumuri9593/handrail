#!/usr/bin/env python3
"""Stop hook: don't let the agent end its turn on a success claim it can't back up.

When the agent's final message says "tests pass", "build succeeds" or "verified"
but this turn has no passing check behind it (or the last check failed), the
hook blocks the stop and tells the agent to run the check or correct the claim.
It fires at most once per turn (stop_hook_active), so it can never loop.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "monitor"))
import transcript_monitor as tm  # noqa: E402


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    if payload.get("stop_hook_active"):
        return 0
    path = payload.get("transcript_path")
    if not path or not os.path.exists(path):
        return 0
    events, flags = tm.monitor_file(path, payload.get("cwd"))
    last_user = max((e.index for e in events if e.kind == "user"), default=-1)
    claims = [f for f in flags if f.check == "unverified-claim" and f.index > last_user]
    if not claims:
        return 0
    reasons = "; ".join(f"{f.message} (\"{f.evidence}\")" for f in claims[:3])
    print(json.dumps({"decision": "block",
                      "reason": "handrail: " + reasons +
                                ". Run the check now and report the real result, or restate the claim as unverified."}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
