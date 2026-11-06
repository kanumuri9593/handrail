"""Shared test helpers. Fake credentials are assembled at runtime so no
secret-shaped string is ever committed to this repo (and push protection stays quiet)."""
import json
import os
import random
import string
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for sub in ("scanner", "monitor", "hooks"):
    sys.path.insert(0, os.path.join(ROOT, sub))

_rng = random.Random(1234)


def _rand(n, alphabet=string.ascii_letters + string.digits):
    return "".join(_rng.choice(alphabet) for _ in range(n))


def fake_aws():
    return "AK" + "IA" + _rand(16, string.ascii_uppercase + string.digits)


def fake_anthropic():
    return "sk-" + "ant-" + "api03-" + _rand(40)


def fake_github():
    return "gh" + "p_" + _rand(36)


def fake_google():
    return "AI" + "za" + _rand(35)


def fake_pem():
    return "-----BEGIN " + "PRIVATE KEY-----\n" + _rand(64) + "\n-----END " + "PRIVATE KEY-----"


def cc_line(role, content, cwd="/work/proj"):
    """One Claude Code transcript line."""
    return json.dumps({"type": role, "cwd": cwd, "message": {"role": role, "content": content}})


def call(id_, name, **inp):
    return {"type": "tool_use", "id": id_, "name": name, "input": inp}


def result(id_, text, is_error=False):
    return {"type": "tool_result", "tool_use_id": id_, "content": text, "is_error": is_error}
