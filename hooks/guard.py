#!/usr/bin/env python3
"""PreToolUse guard for Claude Code (and any agent that can call a hook).

Reads the hook JSON on stdin and answers with a permission decision:
  deny  -> remote code execution, destructive commands, exfiltration,
           switching the agent into bypass mode
  ask   -> credential reads, skipping safety checks, pushes/publishes,
           edits to hooks/CI/agent settings, writing secrets into files
  (no output) -> allow as normal

Env:
  AGENT_GUARD_MODE=enforce (default) | warn   warn = never deny, only ask
  AGENT_GUARD_LOG=<path>   append-only audit log (default ~/.agent-guardrails/audit.jsonl; "off" disables)
"""
from __future__ import annotations

import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scanner"))
sys.path.insert(0, os.path.join(HERE, "..", "monitor"))
import agentscan  # noqa: E402
import transcript_monitor as tm  # noqa: E402

DENY_RULES = {"pipe-to-shell", "encoded-exec", "destructive-command", "data-upload"}
ASK_RULES = {"skip-safety-checks", "env-dump"}


def decide(payload: dict) -> tuple[str, str] | None:
    tool = str(payload.get("tool_name", ""))
    inp = payload.get("tool_input") or {}
    ev = tm.Event("call", 0, tool, inp)
    name = tool.lower()
    cmd = tm.command_skeleton(tm._cmd(ev))

    if cmd:
        for rule_id, pat in agentscan.PROSE_RULES:
            if pat.search(cmd):
                if rule_id in DENY_RULES:
                    return "deny", f"handrail: {agentscan.RULES[rule_id].description}."
                if rule_id in ASK_RULES:
                    return "ask", f"handrail: {agentscan.RULES[rule_id].description}."
        read_cmd = tm.LISTING_ARGS.sub(" ", cmd)
        if tm.SECRET_PATH_RE.search(read_cmd) and not tm.SECRET_PATH_OK.search(read_cmd):
            return "ask", "handrail: this command touches a credential file."
        if tm.OUTWARD_RE.search(cmd):
            return "ask", "handrail: this leaves your machine (push / publish / deploy / POST)."

    path = tm._path(ev)
    if name in tm.READ_TOOLS and path and tm.SECRET_PATH_RE.search(path) and not tm.SECRET_PATH_OK.search(path):
        return "ask", f"handrail: reading a credential file ({os.path.basename(path)})."

    if name in tm.WRITE_TOOLS and path:
        new = tm._new_text(ev)
        if tm.GUARD_FILES.search(path):
            if path.endswith((".json",)) and "bypassPermissions" in new:
                return "deny", "handrail: the agent tried to switch itself into bypassPermissions mode."
            return "ask", "handrail: editing agent permissions, hooks or CI config."
        if any(True for _ in agentscan.find_secrets(new)):
            return "ask", "handrail: this write contains what looks like a live credential."
        if tm.TEST_FILE_RE.search(path) and tm.TEST_SKIP_RE.search(new) and not tm.TEST_SKIP_RE.search(tm._old_text(ev)):
            return "ask", "handrail: this edit skips or neuters a test."
    return None


def log(payload: dict, decision: str, reason: str) -> None:
    target = os.environ.get("AGENT_GUARD_LOG", os.path.expanduser("~/.agent-guardrails/audit.jsonl"))
    if target == "off":
        return
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        ev = tm.Event("call", 0, str(payload.get("tool_name", "")), payload.get("tool_input") or {})
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "session": payload.get("session_id"), "cwd": payload.get("cwd"),
                                 "tool": ev.name, "target": tm._short(tm._cmd(ev) or tm._path(ev), 200),
                                 "decision": decision, "reason": reason}) + "\n")
    except OSError:
        pass


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        return 0
    result = decide(payload)
    if not result:
        return 0
    decision, reason = result
    if decision == "deny" and os.environ.get("AGENT_GUARD_MODE", "enforce") == "warn":
        decision = "ask"
    log(payload, decision, reason)
    print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                             "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
