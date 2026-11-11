"""Deep scan: every file in the repo plus its git history.

Adds to the agent-config scan (agentscan.py):
  - leaked secrets in ANY text file (source, .md, notebooks, configs), comments included
  - hygiene mistakes: committed .env files, service-account keys, hardcoded passwords,
    TLS verification switched off, agent chat logs committed to the repo
  - git history: secrets that were "deleted" but still sit in an old commit, and the commit
    message that tried to remove them ("remove api key")

Secret values are never printed or stored: only redact() output.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess

import agentscan as A

HYGIENE_RULES = [
    A.Rule("committed-env-file", "hygiene", "high", "A .env file with values is committed to the repo"),
    A.Rule("service-account-key", "hygiene", "high", "Cloud service-account key file committed (contains a private key)"),
    A.Rule("hardcoded-credential", "hygiene", "medium", "Password or token hardcoded in source"),
    A.Rule("tls-verify-off", "hygiene", "medium", "TLS certificate checking switched off"),
    A.Rule("agent-history-committed", "hygiene", "medium", "Agent chat history committed (often holds pasted keys, internal URLs, stack traces)"),
    A.Rule("secret-in-history", "credentials", "high", "Secret removed from the code but still in git history: rotate it"),
]
for _r in HYGIENE_RULES:
    A.RULES.setdefault(_r.id, _r)

ENV_NAME_RE = re.compile(r"^\.env(\.(local|dev|development|prod|production|staging|test))?$", re.I)
ENV_SAFE_RE = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)
ENV_LINE_RE = re.compile(r"^\s*(export\s+)?([A-Z][A-Z0-9_]*)\s*=\s*['\"]?([^'\"\s#]+)", re.M)
HARDCODED_RE = re.compile(
    r"""\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"""
    r"""\s*[:=]\s*['"]([^'"\s$%{}<>]{8,})['"]""", re.I)
TLS_OFF_RE = re.compile(
    r"\bverify\s*=\s*False\b|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*['\"]?0|InsecureSkipVerify\s*:\s*true|"
    r"rejectUnauthorized\s*:\s*false|ssl\._create_unverified_context|CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false)|"
    r"\bcurl\b[^\n]*\s(-k|--insecure)\b", re.I)
AGENT_HISTORY_RE = re.compile(r"(^|/)(\.aider\.chat\.history\.md|\.aider\.input\.history|\.specstory/history/[^/]+|"
                              r"claude[-_]?(chat|conversation|transcript)[^/]*\.(md|jsonl|txt))$", re.I)
REMOVE_MSG_RE = re.compile(r"\b(remove|removed|delete|deleted|oops|revoke|rotate|hide|scrub|accidental(ly)?)\b[^\n]{0,40}"
                           r"\b(key|keys|secret|secrets|token|tokens|password|credential|credentials|\.env)\b", re.I)
CODE_EXT = (".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".java", ".kt", ".cs", ".php", ".rs", ".swift",
            ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".sh", ".env", ".dart", ".ipynb")
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".jar", ".lock",
            ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mov", ".mp3", ".wasm", ".so", ".dylib", ".exe", ".bin", ".svg")


FIREBASE_CLIENT_RE = re.compile(r"(google-services\.json|GoogleService-Info\.plist|firebase_options\.dart|firebase[-_.]?config\.(js|ts|json))$", re.I)


def client_key(kind: str, path: str) -> bool:
    """Firebase / Google client API keys ship inside every app build: public by design, low risk if restricted."""
    return kind == "google-api-key" and bool(FIREBASE_CLIENT_RE.search(path or ""))


def _fp(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def hygiene(rel: str, text: str) -> list[A.Finding]:
    out: list[A.Finding] = []
    norm = rel.replace(os.sep, "/")
    base = norm.rsplit("/", 1)[-1]
    in_fixture = bool(A.FIXTURE_PATH_RE.search(norm))
    if ENV_NAME_RE.match(base) and not ENV_SAFE_RE.search(base):
        vals = [(m.group(2), m.group(3)) for m in ENV_LINE_RE.finditer(text)]
        real = [k for k, v in vals if A.SECRET_KEY_NAMES.search(k) and not A.looks_placeholder(v)]
        if real:
            out.append(A.Finding("committed-env-file", "hygiene", "high", rel, 1,
                                 A.RULES["committed-env-file"].description, f"{len(real)} secret-looking values: {', '.join(real[:5])}"))
    if base.endswith(".json") and '"service_account"' in text and '"private_key"' in text and "BEGIN" in text:
        out.append(A.Finding("service-account-key", "hygiene", "high", rel, 1,
                             A.RULES["service-account-key"].description, "private_key: [redacted]"))
    if AGENT_HISTORY_RE.search(norm):
        out.append(A.Finding("agent-history-committed", "hygiene", "medium", rel, 1,
                             A.RULES["agent-history-committed"].description, base))
    if base.lower().endswith(CODE_EXT):
        for ln, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue
            m = HARDCODED_RE.search(line)
            if m and not A.looks_placeholder(m.group(2)) and not re.search(r"(getenv|environ|process\.env|config\[|settings\.)", line):
                out.append(A.Finding("hardcoded-credential", "hygiene", "low" if in_fixture else "medium", rel, ln,
                                     A.RULES["hardcoded-credential"].description, f"{m.group(1)} = {A.redact(m.group(2))}",
                                     downgraded=in_fixture))
            t = TLS_OFF_RE.search(line)
            if t and not A.is_defensive(line, t.start()):
                out.append(A.Finding("tls-verify-off", "hygiene", "low" if in_fixture else "medium", rel, ln,
                                     A.RULES["tls-verify-off"].description, line.strip()[:120], downgraded=in_fixture))
    return out


def scan_all_files(root: str, include_noisy: bool = False) -> A.ScanResult:
    """Agent files get the full rule set; every other text file gets secrets + hygiene."""
    res = A.ScanResult()
    for full in A.discover(root, all_files=True):
        rel = os.path.relpath(full, root) if os.path.isdir(root) else full
        if rel.lower().endswith(SKIP_EXT):
            continue
        try:
            if os.path.getsize(full) > A.MAX_BYTES:
                continue
            with open(full, "rb") as fh:
                raw = fh.read()
        except OSError:
            continue
        if b"\x00" in raw[:4096]:
            continue
        text = raw.decode("utf-8", "replace")
        res.files_scanned += 1
        if A.is_agent_file(rel):
            res.findings += A.scan_text(full, text, include_noisy=include_noisy, display_path=rel)
        else:
            in_fixture = bool(A.FIXTURE_PATH_RE.search(rel.replace(os.sep, "/")))
            for ln, kind, val in A.find_secrets(text):
                if client_key(kind, rel):
                    res.findings.append(A.Finding("leaked-secret", "credentials", "info", rel, ln,
                                                  "Firebase client API key (public by design): make sure API restrictions are set",
                                                  A.redact(val), downgraded=True))
                    continue
                res.findings.append(A.Finding("leaked-secret", "credentials", "low" if in_fixture else "high", rel, ln,
                                              f"Committed {kind}{' (test fixture path)' if in_fixture else ''} — value redacted",
                                              A.redact(val), downgraded=in_fixture))
        res.findings += hygiene(rel, text)
    return res


def scan_history(root: str, max_commits: int = 5000, current_values: set[str] | None = None) -> A.ScanResult:
    """Secrets in any past commit (added or deleted lines), deduplicated by value.
    Values still present in the working tree are skipped: the file scan already reports them."""
    res = A.ScanResult()
    if not os.path.isdir(os.path.join(root, ".git")) and subprocess.run(
            ["git", "-C", root, "rev-parse", "--git-dir"], capture_output=True).returncode != 0:
        return res
    cmd = ["git", "-C", root, "log", "--all", "-p", "--no-color", "--no-ext-diff", "-U0", "--no-renames",
           f"--max-count={max_commits}", "--format=%x00%H%x09%s"]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError):
        return res
    log = p.stdout.decode("utf-8", "replace")
    seen = set(current_values or ())
    commit, subject, path, commits = "", "", "", 0
    for line in log.splitlines():
        if line.startswith("\x00"):
            commit, _, subject = line[1:].partition("\t")
            commits += 1
            continue
        if line.startswith("+++ ") or line.startswith("--- "):
            if line.startswith("+++ "):
                path = line[6:] if line.startswith("+++ b/") else path
            elif line.startswith("--- a/"):
                path = line[6:]
            continue
        if not line or line[0] not in "+-":
            continue
        for _, kind, val in A.find_secrets(line[1:]):
            fp = _fp(val)
            if fp in seen:
                continue
            seen.add(fp)
            how = "deleted in" if line[0] == "-" else "added in"
            if client_key(kind, path):
                res.findings.append(A.Finding("secret-in-history", "credentials", "info", path, 0,
                                              f"Firebase client API key in commit {commit[:8]} (public by design): check API restrictions",
                                              A.redact(val), downgraded=True))
                continue
            hint = f' (commit message: "{subject[:60]}")' if REMOVE_MSG_RE.search(subject) else ""
            res.findings.append(A.Finding("secret-in-history", "credentials", "high", path or "?", 0,
                                          f"{kind} {how} commit {commit[:8]}{hint}: still in git history, rotate it",
                                          A.redact(val)))
    res.files_scanned = commits
    return res


def current_secret_fps(root: str) -> set[str]:
    fps = set()
    for full in A.discover(root, all_files=True):
        try:
            if os.path.getsize(full) > A.MAX_BYTES:
                continue
            with open(full, "r", encoding="utf-8", errors="replace") as fh:
                for _, _, val in A.find_secrets(fh.read()):
                    fps.add(_fp(val))
        except OSError:
            continue
    return fps
