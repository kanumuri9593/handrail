---
description: Audit what the agent actually did in the latest session (risky commands, test tampering, unverified claims)
---

Run the transcript monitor on the most recent session and explain the flags.

1. Run: `python3 "${CLAUDE_PLUGIN_ROOT}/monitor/transcript_monitor.py" --latest`
2. For each flag, say what happened, whether the user asked for it, and whether it needs undoing.
3. Treat `unverified-claim` and `test-tamper` flags as the most important: if one is real, say so plainly.
