#!/usr/bin/env python3
"""agentscan: find dangerous setups in coding-agent instruction and config files.

Scans AGENTS.md, CLAUDE.md, .claude/settings.json, MCP configs, Cursor / Copilot /
Gemini / Windsurf rules and similar files for:

  config       settings that remove the human from the loop
  execution    remote or destructive command patterns
  override     instructions that tell the agent to ignore rules or hide things
  credentials  committed secrets (values are always redacted in output)
  network      exfiltration-shaped instructions
  hidden       invisible / encoded text (opt-in: these are noisy in the wild)

Design rule (from the v0.1 study): structural config rules carry the signal;
hidden-channel rules are ~0% precision on real repos, so they are off by default
(--include-noisy turns them on) and never above "low" severity, except Unicode
bidi controls, which have no benign use in instruction files.

Stdlib only. Python 3.10+.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Iterable, Iterator

__version__ = "0.2.0"

SEVERITIES = ["info", "low", "medium", "high"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# --------------------------------------------------------------------------- #
# File discovery
# --------------------------------------------------------------------------- #

AGENT_FILE_GLOBS = [
    "AGENTS.md", "AGENT.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md",
    ".cursorrules", ".windsurfrules", ".clinerules", ".roorules", ".goosehints",
    ".github/copilot-instructions.md", ".github/instructions/*.md",
    ".github/prompts/*.md", ".github/chatmodes/*.md",
    ".claude/settings.json", ".claude/settings.local.json",
    ".claude/commands/*.md", ".claude/agents/*.md", ".claude/skills/*/SKILL.md",
    ".claude/hooks/*",
    ".mcp.json", "mcp.json", ".vscode/mcp.json", ".cursor/mcp.json",
    ".cursor/rules/*.mdc", ".cursor/rules/*.md", ".gemini/settings.json",
    ".windsurf/rules/*.md", ".amazonq/rules/*.md", ".kiro/steering/*.md",
    "claude_desktop_config.json", ".claude-plugin/plugin.json",
    "hooks/hooks.json",
]
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist",
             "build", ".tox", ".mypy_cache", ".pytest_cache", "vendor"}
MAX_BYTES = 2_000_000


def is_agent_file(relpath: str) -> bool:
    rel = relpath.replace(os.sep, "/")
    base = rel.rsplit("/", 1)[-1]
    for g in AGENT_FILE_GLOBS:
        if "/" in g:
            if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, "*/" + g):
                return True
        elif base == g:
            return True
    return False


def discover(root: str, all_files: bool = False) -> Iterator[str]:
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            if all_files or is_agent_file(rel):
                yield full


def file_family(path: str) -> str:
    p = path.replace(os.sep, "/").lower()
    base = p.rsplit("/", 1)[-1]
    if "mcp" in base and base.endswith(".json") or base == "claude_desktop_config.json":
        return "mcp"
    if p.endswith(".claude/settings.json") or p.endswith(".claude/settings.local.json") \
            or p.endswith(".gemini/settings.json"):
        return "agent-settings"
    if base == "hooks.json" or "/.claude/hooks/" in p:
        return "hooks"
    if base.endswith(".json"):
        return "json"
    return "prose"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    rule: str
    category: str
    severity: str
    path: str
    line: int
    message: str
    evidence: str = ""
    downgraded: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Rule:
    id: str
    category: str
    severity: str
    description: str
    noisy: bool = False


RULES: dict[str, Rule] = {r.id: r for r in [
    # config (structural, high precision)
    Rule("mcp-auto-approve", "config", "high", "MCP server auto-approves tool calls (autoApprove / alwaysAllow / trust)"),
    Rule("agent-permission-mode", "config", "high", "Agent default mode bypasses permission prompts"),
    Rule("agent-auto-enable-mcp", "config", "medium", "All project MCP servers enabled without per-server approval"),
    Rule("agent-broad-permissions", "config", "high", "Allow rule grants unrestricted shell or destructive commands"),
    Rule("agent-skip-dangerous-prompt", "config", "high", "Setting skips the dangerous-mode confirmation"),
    Rule("mcp-inline-secret", "credentials", "high", "API key or token written inline in an MCP server env/args/headers"),
    Rule("mcp-runs-remote-script", "execution", "high", "MCP server command downloads and runs remote code"),
    Rule("mcp-unpinned-package", "config", "low", "MCP server runs an unpinned npx/uvx package (new code on every start)"),
    Rule("mcp-plain-http", "network", "medium", "MCP server reached over plain http to a non-local host"),
    Rule("hook-remote-exec", "execution", "high", "Hook command downloads and runs remote code"),
    # execution (prose + config)
    Rule("pipe-to-shell", "execution", "medium", "Downloads a script and pipes it into a shell"),
    Rule("encoded-exec", "execution", "medium", "Decodes an encoded payload and executes it"),
    Rule("destructive-command", "execution", "medium", "Instructs a destructive command (rm -rf /, force push to main, DROP DATABASE)"),
    Rule("skip-safety-checks", "execution", "medium", "Tells the agent to bypass hooks, tests or verification (--no-verify, --dangerously-skip-permissions)"),
    Rule("env-dump", "execution", "medium", "Dumps the full environment (printenv / env / os.environ) to output or network"),
    # override
    Rule("prompt-override", "override", "high", "Tries to override the agent's instructions or system prompt"),
    Rule("no-user-confirmation", "override", "medium", "Tells the agent to act without asking the user"),
    Rule("conceal-from-user", "override", "high", "Tells the agent to hide actions or results from the user"),
    Rule("disable-guardrails", "override", "high", "Tells the agent to turn off safety settings, hooks or monitoring"),
    # credentials
    Rule("leaked-secret", "credentials", "high", "Committed credential (value redacted)"),
    Rule("credential-path", "credentials", "low", "Instructs reading credential stores (~/.ssh, ~/.aws, .env)", noisy=True),
    # network
    Rule("data-upload", "network", "medium", "Instructs sending local files or state to an external host"),
    Rule("exfil-endpoint", "network", "low", "References a known request-capture / tunnel endpoint", noisy=True),
    # hidden (noisy; opt-in)
    Rule("bidi-control", "hidden", "high", "Unicode bidirectional control characters (Trojan Source)"),
    Rule("zero-width-chars", "hidden", "low", "Zero-width characters", noisy=True),
    Rule("unicode-tag-chars", "hidden", "high", "Unicode tag characters (invisible ASCII smuggling)"),
    Rule("base64-text-blob", "hidden", "info", "Long base64 blob in an instruction file", noisy=True),
    Rule("html-comment-directive", "hidden", "low", "Imperative instruction hidden in an HTML comment", noisy=True),
]}


# --------------------------------------------------------------------------- #
# Secret detection + redaction
# --------------------------------------------------------------------------- #

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
]

PLACEHOLDER_RE = re.compile(
    r"(your[_\-]?|example|placeholder|dummy|fake|sample|test|xxxx|\*\*\*\*|<[^>]+>|\$\{|\{\{|changeme|redacted|EXAMPLE)",
    re.I)
FIXTURE_PATH_RE = re.compile(r"(^|/)(tests?|fixtures?|__fixtures__|testdata|examples?|mocks?|dummy)(/|$)", re.I)

SECRET_KEY_NAMES = re.compile(
    r"(api[_-]?key|token|secret|password|passwd|auth|bearer|private[_-]?key|access[_-]?key|credential)", re.I)


def redact(value: str) -> str:
    """Never return a usable secret: keep a short prefix for triage only."""
    v = value.strip()
    if v.startswith("-----BEGIN"):
        return "-----BEGIN …PRIVATE KEY----- [redacted]"
    if len(v) <= 8:
        return "[redacted]"
    return v[:4] + "…[redacted " + str(len(v)) + " chars]"


def looks_placeholder(value: str) -> bool:
    if not value or len(value) < 12:
        return True
    if PLACEHOLDER_RE.search(value):
        return True
    if value.startswith("$") or value.startswith("env:"):
        return True
    # low entropy / repeated characters
    if len(set(value)) <= 4:
        return True
    return False


def find_secrets(text: str) -> Iterator[tuple[int, str, str]]:
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, pat in SECRET_PATTERNS:
            for m in pat.finditer(line):
                val = m.group(0)
                if kind != "private-key" and looks_placeholder(val):
                    continue
                yield lineno, kind, val


# --------------------------------------------------------------------------- #
# Prose rules
# --------------------------------------------------------------------------- #

NEGATION_RE = re.compile(
    r"\b(never|don'?t|do not|must not|mustn'?t|should not|shouldn'?t|avoid|no |not |forbid|prohibit|"
    r"disallow|deny|block|refuse|without (?:first )?asking|unless|warn)", re.I)

PROSE_RULES: list[tuple[str, re.Pattern]] = [
    ("pipe-to-shell", re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|k|fi)?sh\b|\biex\s*\(\s*(iwr|irm|New-Object)", re.I)),
    ("encoded-exec", re.compile(r"base64\s+(-d|--decode|-D)\b[^\n]*\|\s*(ba|z)?sh\b|eval\s*\(\s*(atob|Buffer\.from)|exec\s*\(\s*base64\.b64decode|powershell[^\n]*-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I)),
    ("destructive-command", re.compile(r"\brm\s+-(rf|fr|r\s+-f)\s+(/|~|\$HOME|\*)(\s|$)|git\s+push\s+(-f|--force)\b[^\n]*\b(main|master)\b|\bDROP\s+(DATABASE|SCHEMA)\b|mkfs\.|dd\s+if=[^\n]*of=/dev/(sd|disk|nvme)", re.I)),
    ("skip-safety-checks", re.compile(r"--no-verify\b|--dangerously-skip-permissions\b|--yolo\b|--dangerously-bypass-approvals|HUSKY=0|SKIP=\S*\s+git commit", re.I)),
    ("env-dump", re.compile(r"(^|[;&|`(:]\s*|\$\s+)(printenv|env)\s*(\|\s*(curl|nc|wget|tee|base64)|>\s*[\w./~-]+)|JSON\.stringify\(\s*process\.env\s*\)|dict\(\s*os\.environ\s*\)|\bprintenv\s*$", re.I | re.M)),
    ("prompt-override", re.compile(r"\b(ignore|disregard|forget|override)\b[^\n.]{0,40}\b(previous|prior|above|earlier|all|system|your)\b[^\n.]{0,30}\b(instructions?|prompts?|rules?|guidelines?)\b|\bnew system prompt\b|\byou are now (?:in )?(DAN|developer mode|jailbroken)", re.I)),
    ("no-user-confirmation", re.compile(r"\b(without|never|don'?t|do not|no need to)\s+(ask(ing)?|prompt(ing)?|confirm(ing|ation)?|check(ing)? with|wait(ing)? for)\b[^\n.]{0,30}\b(user|me|human|permission|approval|confirmation)\b|\bauto[- ]?(approve|accept|confirm)\s+(all|every)", re.I)),
    ("conceal-from-user", re.compile(r"\b(don'?t|do not|never)\s+(tell|inform|mention|show|reveal|report|let)\b[^\n.]{0,25}\b(the )?(user|human|developer|owner|reviewer)\b|\b(hide|conceal)\b[^\n.]{0,30}\bfrom (the )?(user|human|reviewer|logs?)\b|\b(delete|clear|wipe|truncate|erase)\b[^\n.]{0,20}\b((shell|bash|zsh|command|terminal) history|transcripts?|audit logs?|session logs?)\b|\bhistory\s+-c\b", re.I)),
    ("disable-guardrails", re.compile(r"\b(disable|turn off|remove|bypass|delete)\b[^\n.]{0,30}\b(safety|guardrails?|hooks?|sandbox|permission (checks?|prompts?)|monitoring|telemetry audit|security (checks?|scan(ner|s)?))\b", re.I)),
    ("data-upload", re.compile(r"\b(curl|wget|http(ie)?|fetch|requests\.post)\b[^\n]*(-d\s*@|--data(-binary)?\s*@|-F\s*\S*=@|--upload-file|-T\s)[^\n]*(~|\.env|\.ssh|\.aws|id_rsa|/etc/passwd|\$HOME)", re.I)),
    ("credential-path", re.compile(r"(~|\$HOME)/\.(ssh|aws|gnupg|kube|docker/config\.json|netrc)|\bid_(rsa|ed25519)\b|\bcat\s+\.env\b", re.I)),
    ("exfil-endpoint", re.compile(r"\b(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|oast\.(pro|fun|live|site)|burpcollaborator\.net|requestcatcher\.com|beeceptor\.com)\b", re.I)),
]

HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
IMPERATIVE_RE = re.compile(r"\b(ignore|you must|always|never tell|run|execute|send|upload|disable|assistant|agent|AI|LLM)\b", re.I)
BUILD_BANNER_RE = re.compile(r"(auto-?generated|do not edit|generated by|prettier-ignore|markdownlint|toc|eslint|vale|begin|end)", re.I)
ZW_RE = re.compile("[\u200b\u200c\u200d\u2060\ufeff]")
BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
TAG_RE = re.compile("[\U000e0000-\U000e007f]")
B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_\-.])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=])")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ")


def is_defensive(line: str, start: int) -> bool:
    """True if the match sits after a negation ("never run curl | bash")."""
    window = line[max(0, start - 60):start]
    return bool(NEGATION_RE.search(window))


def scan_prose(path: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, 1):
        for rule_id, pat in PROSE_RULES:
            m = pat.search(line)
            if not m:
                continue
            rule = RULES[rule_id]
            sev = rule.severity
            downgraded = False
            # Rules whose regex already encodes the negation (no-user-confirmation,
            # conceal-from-user) are not downgraded by it.
            if rule_id not in ("no-user-confirmation", "conceal-from-user") and is_defensive(line, m.start()):
                sev, downgraded = "info", True
            out.append(Finding(rule_id, rule.category, sev, path, lineno, rule.description,
                               _snippet(line, m), downgraded))
        if BIDI_RE.search(line):
            out.append(Finding("bidi-control", "hidden", "high", path, lineno, RULES["bidi-control"].description,
                               _visible(line)))
        if TAG_RE.search(line):
            out.append(Finding("unicode-tag-chars", "hidden", "high", path, lineno,
                               RULES["unicode-tag-chars"].description, _decode_tags(line)))
        if ZW_RE.search(line):
            out.append(Finding("zero-width-chars", "hidden", "low", path, lineno, RULES["zero-width-chars"].description,
                               _visible(line)))
        for m in B64_RE.finditer(line):
            if JWT_RE.search(line):
                continue
            out.append(Finding("base64-text-blob", "hidden", "info", path, lineno,
                               RULES["base64-text-blob"].description, m.group(0)[:24] + "…"))
            break
    for m in HTML_COMMENT_RE.finditer(text):
        body = m.group(1)
        if IMPERATIVE_RE.search(body) and not BUILD_BANNER_RE.search(body):
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(Finding("html-comment-directive", "hidden", "low", path, lineno,
                               RULES["html-comment-directive"].description, " ".join(body.split())[:120]))
    return out


def _snippet(line: str, m: re.Match) -> str:
    s = max(0, m.start() - 20)
    e = min(len(line), m.end() + 20)
    snip = line[s:e].strip()
    for _, pat in SECRET_PATTERNS:
        snip = pat.sub(lambda mm: redact(mm.group(0)), snip)
    return snip[:160]


def _visible(line: str) -> str:
    def esc(c: str) -> str:
        return f"<U+{ord(c):04X}>"
    return re.sub("[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]", lambda m: esc(m.group(0)), line.strip())[:160]


def _decode_tags(line: str) -> str:
    hidden = "".join(chr(ord(c) - 0xE0000) for c in line if 0xE0000 <= ord(c) <= 0xE007F)
    return ("hidden text: " + hidden)[:160]


# --------------------------------------------------------------------------- #
# Structural JSON rules
# --------------------------------------------------------------------------- #

BROAD_ALLOW = re.compile(r"^(Bash|Shell|run_terminal_cmd|terminal)(\(\s*\*?\s*\)|\(\s*\*\s*:?\s*\*?\s*\))?$|^Bash\(\s*(rm|sudo|curl|wget|git push|chmod|dd|mkfs)\b[^)]*\*", re.I)
REMOTE_EXEC_ARGS = re.compile(r"(curl|wget|iwr|irm)\b.*\|\s*(ba|z)?sh|https?://\S+\.(sh|ps1|py)\b", re.I)
UNPINNED_PKG = re.compile(r"^(@[\w.\-]+/)?[\w.\-]+$")


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 1


def _iter_mcp_servers(data: dict) -> Iterator[tuple[str, dict]]:
    for key in ("mcpServers", "servers", "mcp_servers", "context_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, cfg in block.items():
                if isinstance(cfg, dict):
                    yield name, cfg
    mcp = data.get("mcp")
    if isinstance(mcp, dict):
        yield from _iter_mcp_servers(mcp)


def scan_json(path: str, text: str, data) -> list[Finding]:
    out: list[Finding] = []
    if not isinstance(data, dict):
        return out

    def add(rule_id: str, needle: str, evidence: str, sev: str | None = None):
        r = RULES[rule_id]
        out.append(Finding(rule_id, r.category, sev or r.severity, path, _line_of(text, needle), r.description, evidence))

    # --- agent settings (Claude Code, Gemini, etc.) ---
    perms = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    mode = perms.get("defaultMode") or data.get("defaultMode") or data.get("approvalMode") or data.get("approval_mode")
    if isinstance(mode, str) and mode.lower() in ("bypasspermissions", "yolo", "never", "full-auto", "auto"):
        add("agent-permission-mode", mode, f"defaultMode: {mode}")
    if data.get("enableAllProjectMcpServers") is True:
        add("agent-auto-enable-mcp", "enableAllProjectMcpServers", "enableAllProjectMcpServers: true")
    if data.get("skipDangerousModePermissionPrompt") is True or perms.get("skipDangerousModePermissionPrompt") is True:
        add("agent-skip-dangerous-prompt", "skipDangerousModePermissionPrompt", "skipDangerousModePermissionPrompt: true")
    allow = perms.get("allow") or []
    if isinstance(allow, list):
        for entry in allow:
            if isinstance(entry, str) and BROAD_ALLOW.search(entry.strip()):
                add("agent-broad-permissions", entry, f"allow: {entry}")
    for flag in ("dangerouslySkipPermissions", "autoApproveAll", "yolo"):
        if data.get(flag) is True:
            add("agent-permission-mode", flag, f"{flag}: true")

    # --- hooks ---
    hooks = data.get("hooks")
    if isinstance(hooks, dict):
        for event, groups in hooks.items():
            for cmd in _walk_strings(groups, key="command"):
                if REMOTE_EXEC_ARGS.search(cmd):
                    add("hook-remote-exec", cmd[:40], f"{event}: {cmd[:120]}")

    # --- MCP servers ---
    for name, cfg in _iter_mcp_servers(data):
        if cfg.get("autoApprove") or cfg.get("alwaysAllow") or cfg.get("trust") is True \
                or cfg.get("autoApproveAll") is True:
            val = cfg.get("autoApprove") or cfg.get("alwaysAllow") or "true"
            add("mcp-auto-approve", name, f"{name}: auto-approves {_short(val)}")
        cmd = str(cfg.get("command", ""))
        args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
        full = " ".join([cmd] + [str(a) for a in args])
        if REMOTE_EXEC_ARGS.search(full):
            add("mcp-runs-remote-script", name, f"{name}: {_short(full)}")
        base_cmd = os.path.basename(cmd)
        if base_cmd in ("npx", "uvx", "bunx", "pnpx"):
            pkgs = [a for a in args if isinstance(a, str) and not a.startswith("-")]
            if pkgs:
                pkg = pkgs[0]
                pinned = ("@" in pkg.lstrip("@") and not pkg.endswith("@latest")) or "==" in pkg
                if not pinned and (UNPINNED_PKG.match(pkg) or pkg.endswith("@latest")):
                    add("mcp-unpinned-package", name, f"{name}: {base_cmd} {pkg}")
        url = cfg.get("url") or cfg.get("serverUrl") or ""
        if isinstance(url, str) and url.startswith("http://") and not re.match(r"http://(localhost|127\.|0\.0\.0\.0|\[::1\])", url):
            add("mcp-plain-http", name, f"{name}: {url[:80]}")
        # inline secrets in env / headers / args
        for section in ("env", "headers"):
            block = cfg.get(section)
            if isinstance(block, dict):
                for k, v in block.items():
                    if isinstance(v, str) and SECRET_KEY_NAMES.search(k) and not looks_placeholder(v) \
                            and not re.fullmatch(r"\$\{?[A-Z_][A-Z0-9_]*\}?", v.strip()):
                        add("mcp-inline-secret", k, f"{name}.{section}.{k} = {redact(v)}")
        for i, a in enumerate(args):
            if isinstance(a, str) and re.match(r"^--?(api[-_]?key|token|secret|password)=", a, re.I):
                val = a.split("=", 1)[1]
                if not looks_placeholder(val):
                    add("mcp-inline-secret", a[:12], f"{name}.args[{i}] = {a.split('=')[0]}={redact(val)}")
    return out


def _walk_strings(obj, key: str | None = None) -> Iterator[str]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str) and (key is None or k == key):
                yield v
            else:
                yield from _walk_strings(v, key)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v, key)


def _short(v) -> str:
    s = v if isinstance(v, str) else json.dumps(v)
    return s if len(s) <= 100 else s[:97] + "…"


def _strip_jsonc(text: str) -> str:
    text = re.sub(r"(?<![:\"\\])//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r",\s*([}\]])", r"\1", text)
    return text


# --------------------------------------------------------------------------- #
# Scan driver
# --------------------------------------------------------------------------- #

@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)


def scan_text(path: str, text: str, include_noisy: bool = False, display_path: str | None = None) -> list[Finding]:
    disp = display_path or path
    fam = file_family(path)
    findings: list[Finding] = []
    data = None
    if path.lower().endswith(".json"):
        try:
            data = json.loads(text)
        except ValueError:
            try:
                data = json.loads(_strip_jsonc(text))
            except ValueError:
                data = None
    if data is not None:
        findings += scan_json(disp, text, data)
        # Run execution/override prose rules on string values only, not on deny lists.
        deny = set()
        perms = data.get("permissions") if isinstance(data, dict) and isinstance(data.get("permissions"), dict) else {}
        for d in perms.get("deny", []) or []:
            if isinstance(d, str):
                deny.add(d)
        strings = [s for s in _walk_strings(data) if s not in deny]
        for f in scan_prose(disp, "\n".join(strings)):
            if f.rule in ("pipe-to-shell", "encoded-exec", "destructive-command", "prompt-override",
                          "data-upload", "env-dump", "exfil-endpoint"):
                f.line = _line_of(text, f.evidence[:20]) if f.evidence else 1
                findings.append(f)
    else:
        findings += scan_prose(disp, text)

    # Secrets: every file type. MCP inline-secret already covers env/headers.
    in_fixture = bool(FIXTURE_PATH_RE.search(disp.replace(os.sep, "/")))
    already = {(f.line) for f in findings if f.rule == "mcp-inline-secret"}
    for lineno, kind, val in find_secrets(text):
        if lineno in already:
            continue
        sev = "low" if in_fixture else "high"
        findings.append(Finding("leaked-secret", "credentials", sev, disp, lineno,
                                f"Committed {kind}{' (test fixture path)' if in_fixture else ''} — value redacted",
                                redact(val), downgraded=in_fixture))

    if not include_noisy:
        findings = [f for f in findings if not RULES[f.rule].noisy]
    # de-duplicate same rule on same line
    seen, uniq = set(), []
    for f in findings:
        k = (f.rule, f.path, f.line)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def scan_path(root: str, include_noisy: bool = False, all_files: bool = False) -> ScanResult:
    res = ScanResult()
    for full in discover(root, all_files=all_files):
        try:
            if os.path.getsize(full) > MAX_BYTES:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        res.files_scanned += 1
        rel = os.path.relpath(full, root) if os.path.isdir(root) else full
        res.findings += scan_text(full, text, include_noisy=include_noisy, display_path=rel)
    res.findings.sort(key=lambda f: (-SEV_RANK[f.severity], f.path, f.line))
    return res


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

COLORS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}


def format_text(res: ScanResult, min_sev: str, color: bool) -> str:
    lines = []
    shown = [f for f in res.findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]]
    for f in shown:
        sev = f.severity.upper()
        if color:
            sev = COLORS[f.severity] + sev + "\033[0m"
        lines.append(f"{sev:<6} {f.rule:<26} {f.path}:{f.line}  {f.message}")
        if f.evidence:
            lines.append(f"       └ {f.evidence}")
    counts = {s: sum(1 for f in res.findings if f.severity == s) for s in SEVERITIES}
    lines.append("")
    lines.append(f"agentscan {__version__}: {res.files_scanned} agent files scanned · "
                 f"high {counts['high']} · medium {counts['medium']} · low {counts['low']} · info {counts['info']}")
    return "\n".join(lines)


def format_sarif(res: ScanResult, min_sev: str) -> dict:
    level = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    used = sorted({f.rule for f in res.findings})
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agentscan", "version": __version__,
                "informationUri": "https://github.com/kanumuri9593/agent-guardrails-lab",
                "rules": [{"id": r, "shortDescription": {"text": RULES[r].description},
                           "properties": {"category": RULES[r].category,
                                          "security-severity": {"high": "8.0", "medium": "5.0", "low": "3.0", "info": "1.0"}[RULES[r].severity]}}
                          for r in used]}},
            "results": [{
                "ruleId": f.rule, "level": level[f.severity],
                "message": {"text": f"{f.message}" + (f" — {f.evidence}" if f.evidence else "")},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path.replace(os.sep, "/")},
                                                    "region": {"startLine": max(1, f.line)}}}],
            } for f in res.findings if SEV_RANK[f.severity] >= SEV_RANK[min_sev]],
        }],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentscan", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", default=["."], help="repo folders or files to scan")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", "-o", help="write report to this file instead of stdout")
    ap.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this")
    ap.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="none",
                    help="exit 1 if any finding is at or above this severity (for CI)")
    ap.add_argument("--include-noisy", action="store_true",
                    help="also run low-precision hidden-channel rules (zero-width, base64, html comments)")
    ap.add_argument("--all-files", action="store_true", help="scan every file, not just known agent files")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"agentscan {__version__}")
    a = ap.parse_args(argv)

    if a.list_rules:
        for r in RULES.values():
            print(f"{r.id:<28} {r.category:<12} {r.severity:<7} {'(opt-in) ' if r.noisy else ''}{r.description}")
        return 0

    res = ScanResult()
    for p in a.paths:
        r = scan_path(p, include_noisy=a.include_noisy, all_files=a.all_files)
        res.files_scanned += r.files_scanned
        res.findings += r.findings

    if a.format == "json":
        body = json.dumps({"version": __version__, "files_scanned": res.files_scanned,
                           "findings": [f.to_dict() for f in res.findings
                                        if SEV_RANK[f.severity] >= SEV_RANK[a.min_severity]]}, indent=2)
    elif a.format == "sarif":
        body = json.dumps(format_sarif(res, a.min_severity), indent=2)
    else:
        body = format_text(res, a.min_severity, color=not a.no_color and sys.stdout.isatty() and not a.output)

    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(body + "\n")
        if a.format != "text":
            print(format_text(res, "medium", color=False).splitlines()[-1])
    else:
        print(body)

    if a.fail_on != "none" and any(SEV_RANK[f.severity] >= SEV_RANK[a.fail_on] for f in res.findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
