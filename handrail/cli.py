"""handrail: one command for every place an agent runs.

    handrail scan [paths] [--home]       risky agent setups in a repo or on this machine
    handrail audit [session.jsonl|--latest]  what an agent actually did in a session
    handrail guard                        Claude Code PreToolUse hook (reads JSON on stdin)
    handrail stop-check                   Claude Code Stop hook (blocks unverified "tests pass")
    handrail init claude [--global] [--write]  wire guard + stop-check into Claude Code
    handrail rules                        list every scanner rule
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys

from handrail import __version__

_HERE = os.path.dirname(os.path.abspath(__file__))


def _code_dirs() -> list[str]:
    """Rule code lives in scanner/, monitor/ and hooks/: beside this package in a checkout,
    or inside it (handrail/_scanner ...) when installed from pip or npm."""
    out = []
    for sub, inner in (("scanner", "_scanner"), ("monitor", "_monitor"), ("hooks", "_hooks")):
        for cand in (os.path.join(_HERE, inner), os.path.join(os.path.dirname(_HERE), sub)):
            if os.path.isdir(cand):
                out.append(cand)
                break
    return out


for _d in _code_dirs():
    if _d not in sys.path:
        sys.path.insert(0, _d)


def _hook_command(name: str) -> str:
    """The command Claude Code runs. Prefer the installed `handrail` binary; fall back to this Python."""
    exe = os.environ.get("HANDRAIL_BIN") or shutil.which("handrail")
    if exe:
        return f"{shlex.quote(exe)} {name}"
    return f"{shlex.quote(sys.executable)} -m handrail {name}"


def hooks_config(cmd=_hook_command) -> dict:
    return {"hooks": {
        "PreToolUse": [{"matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit",
                        "hooks": [{"type": "command", "command": cmd("guard"), "timeout": 10}]}],
        "Stop": [{"hooks": [{"type": "command", "command": cmd("stop-check"), "timeout": 20}]}],
    }}


def merge_hooks(settings: dict, add: dict) -> dict:
    """Add Handrail's hooks without touching anything else; running twice changes nothing."""
    out = json.loads(json.dumps(settings))
    hooks = out.setdefault("hooks", {})
    for event, groups in add["hooks"].items():
        have = hooks.setdefault(event, [])
        existing = {h.get("command") for g in have for h in g.get("hooks", [])}
        for g in groups:
            if not any(h["command"] in existing for h in g["hooks"]):
                have.append(g)
    return out


def _init(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="handrail init", description="Wire Handrail into an agent.")
    ap.add_argument("agent", choices=["claude"])
    ap.add_argument("--global", dest="glob", action="store_true", help="~/.claude/settings.json instead of this project")
    ap.add_argument("--write", action="store_true", help="write the file (default: print what would change)")
    a = ap.parse_args(argv)
    path = os.path.expanduser("~/.claude/settings.json") if a.glob else os.path.join(".claude", "settings.json")
    try:
        with open(path, encoding="utf-8") as fh:
            current = json.load(fh)
    except FileNotFoundError:
        current = {}
    except ValueError:
        print(f"{path} is not valid JSON; fix it first, nothing written.", file=sys.stderr)
        return 2
    merged = merge_hooks(current, hooks_config())
    if merged == current:
        print(f"Handrail is already wired into {path}.")
        return 0
    if not a.write:
        print(f"Would write {path}:\n{json.dumps(merged, indent=2)}\n\nRe-run with --write to apply.")
        return 0
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2)
        fh.write("\n")
    print(f"Handrail guard + stop-check added to {path}. Restart Claude Code to load them.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd in ("-V", "--version", "version"):
        print(f"handrail {__version__}")
        return 0
    if cmd == "scan":
        import agentscan
        return agentscan.main(rest)
    if cmd == "rules":
        import agentscan
        return agentscan.main(["--list-rules"])
    if cmd == "audit":
        import transcript_monitor
        return transcript_monitor.main(rest)
    if cmd == "guard":
        import guard
        return guard.main()
    if cmd == "stop-check":
        import stop_check
        return stop_check.main()
    if cmd == "init":
        return _init(rest)
    print(f"handrail: unknown command '{cmd}'. Try: handrail --help", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
