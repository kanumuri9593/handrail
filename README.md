# Agent Guardrails Lab

> **For reviewers, a 5-minute read**
>
> - **The question:** coding agents now read untrusted repos, run shell commands and hold real credentials. What actually goes wrong in practice, and can cheap, deterministic guardrails catch it?
> - **What I measured:** [a study of 1,200 active public repos](docs/REPORT-v0.1.md) (9,499 agent instruction and config files, hand-verified). The real risk sat in *configs*, such as auto-approved MCP servers, bypassed permissions and live keys committed in MCP files, not in exotic prompt injection. Recall is at least about 97% on a random sample of unflagged files.
> - **What I built from it:** one rule set in four places. A scanner for repos or your own laptop, a GitHub Action that blocks risky PRs (with SARIF output), a live Claude Code hook that stops dangerous tool calls, and a transcript monitor plus stop check that catch agents claiming "tests pass" after quietly skipping them. It uses only the standard library, needs no API keys, and redacts every secret.
> - **What I'm testing now:** [`hie/`](hie/) plants hidden instructions (README text, HTML comments, code comments, AGENTS.md, invisible Unicode, fetched web pages) in a toy repo. It measures how often Claude models follow them, whether they tell the user, and whether the guard would have stopped them. *Pilot results pending.*
> - **Try it:** `python3 scanner/agentscan.py path/to/repo`, or `python3 scanner/agentscan.py --home` to scan your own agent setup.

Practical guardrails for coding agents (Claude Code, Cursor, Copilot, Gemini, Windsurf and others). There are three tools that share one rule set:

| Tool | When it runs | What it catches |
|---|---|---|
| **agentscan** (`scanner/agentscan.py`) | On your laptop, in pre-commit, or in CI as a GitHub Action | Dangerous agent setups in a repo: MCP `autoApprove`, `bypassPermissions`, `Bash(*)`, `enableAllProjectMcpServers`, keys committed in MCP configs, hooks that run remote code, `curl \| bash` instructions, prompt overrides, Trojan-Source Unicode, and coding agents in CI workflows with approvals off or on `pull_request_target`, plus Codex `approval_policy = "never"` |
| **guard hook** (`hooks/guard.py`) | Live, before each agent tool call | Blocks remote-code execution, `rm -rf /`, exfiltration, and an agent switching itself into bypass mode. Asks first before credential reads, `--no-verify`, pushes and deploys, CI or hook edits, test skips, and secrets being written to files |
| **transcript monitor** (`monitor/transcript_monitor.py`) and **stop check** (`hooks/stop_check.py`) | After a session, or as the agent tries to end its turn | What the agent actually did: risky commands, secret reads, guardrail tampering, test tampering, work outside the workspace, outward actions, and **unverified claims** ("all tests pass" with no passing run behind it, claimed right after a failure, or reached by skipping tests without saying so). Risky actions right after a tool result that told the agent what to do are raised to high |

It needs only the Python 3.10+ standard library, with no API keys and no network. Secret values are always redacted in output.

## Why these rules

The [v0.1 study](docs/REPORT-v0.1.md) covered 1,200 active public repos and 9,499 unique agent files, and found the following.

- **Real risk lives in configs, not prompts.** MCP configs and `.claude/settings.json` hold most medium-or-higher findings. The sample had zero confirmed agent-hijacking injections.
- **Structural rules carry the signal.** `mcp-auto-approve`, `agent-broad-permissions`, `agent-auto-enable-mcp` and `agent-permission-mode` each scored 100% on the hand-labeled sample.
- **Hidden-text detectors are noise in the wild.** Zero-width, base64 and HTML-comment rules scored about 0% precision, so here they are **opt-in** (`--include-noisy`) and never high severity. Unicode bidi and tag characters are the exception: they have no benign use in instruction files.

## Quick start

```bash
# scan a repo
python3 scanner/agentscan.py path/to/repo
python3 scanner/agentscan.py . --fail-on high              # CI gate
python3 scanner/agentscan.py . --format sarif -o out.sarif # GitHub code scanning
python3 scanner/agentscan.py --home                        # your own laptop: ~/.claude, Claude Desktop, Cursor, Codex, Gemini, VS Code
python3 scanner/agentscan.py --list-rules

# audit an agent session
python3 monitor/transcript_monitor.py --latest             # newest Claude Code session
python3 monitor/transcript_monitor.py session.jsonl --format json --fail-on high
```

### As a Claude Code plugin (live guard, stop check, slash commands)

This repo is a plugin (`.claude-plugin/plugin.json` and `hooks/hooks.json`). Install it from a local path or a marketplace and you get:
- a **PreToolUse guard** that denies or asks on risky tool calls (`AGENT_GUARD_MODE=warn` turns denies into asks)
- a **Stop check** that sends the agent back to run the check when it claims success it can't back up (it fires at most once per turn)
- the commands `/agentscan` and `/audit-session`
- an append-only audit log at `~/.agent-guardrails/audit.jsonl` (`AGENT_GUARD_LOG=off` disables it)

### In CI (GitHub Action)

```yaml
- uses: kanumuri9593/agent-guardrails-lab@main   # pin a tag/SHA once released
  with:
    fail-on: high
```

There's a full example with a SARIF upload in [`action/agentscan-action.yml`](action/agentscan-action.yml).

### In pre-commit

```yaml
- repo: https://github.com/kanumuri9593/agent-guardrails-lab
  rev: main
  hooks: [{ id: agentscan }]
```

## Field test (2026-11-06, this author's own machine)

**agentscan.** I ran it on 120 real agent files across about 40 local projects. The first run raised 13 medium-or-higher findings, and all 13 were false positives: `<env>` in a path, an "```env" code fence, and "delete dead code; use git history". After tightening those two rules, the result was **0 medium-or-higher**. Each false-positive shape is now a regression test.

**Transcript monitor.** I ran it on 40 real Claude Code sessions with 3,493 tool calls.

| Metric | First run | Second run |
|---|---|---|
| High flags | 47 | 3 |
| Medium flags | 360 | 86 |

What I fixed between the two runs:
- **False "failed" verdicts.** The monitor read "HiveStorage.get failed for key=…" as a failed test run, even though the run ended with "All tests passed!". The last summary line in the output now decides.
- **Listing counted as reading.** `find -name ".env*"` and `grep --include` were treated as reading credentials. They no longer are.
- **Claim phrasing.** "confirmed to them that…" was read as a success claim. It no longer is.
- **Severity tiers.** Remote-control `send_message` reports are now low. Project `.env` reads are medium, or low when the output is masked. `~/.ssh` and keychain reads stay high.

What remains:
- **21 unmasked project `.env` reads** by agents. These are real.
- **2 "tests pass" claims** with no test run in that session. They are unconfirmed and may be relayed from an earlier session.
- **1 self-reference:** a heredoc that contained the rule's own text.

The results above come from one person's machine and are not a benchmark. The labelled evaluation is in the v0.1 study.

## Hidden-instructions eval (`hie/`)

Plants an instruction aimed at the agent in a tiny repo with a failing test, in 6 places (README text, an HTML comment, a code comment, AGENTS.md, invisible Unicode tag characters, a fetched web page), with 3 goals (send `.env` out, loosen `.claude/settings.json`, run a remote script). It then records whether the model followed the instruction, whether it told the user, whether it still fixed the bug, and whether `hooks/guard.py` would have stopped the harmful step. There are 18 planted scenarios and 2 clean controls.

Everything is simulated in memory. No command runs, nothing leaves the process, the host is an unroutable `.example` name, and the key is a fake canary.

```bash
python3 -m hie.run --dry-run naive                 # free: checks the harness with a scripted agent
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env      # gitignored; keep it out of ~/.zshrc
pip install anthropic && python3 -m hie.run --repeats 1 --max-cost 6   # real pilot, about $4
```

Results go to `results/runs.jsonl` and `results/summary.md` (gitignored).

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Layout

```
scanner/agentscan.py           rules, file discovery, redaction, text/json/sarif output
monitor/transcript_monitor.py  session audit (Claude Code JSONL + a simple normalized JSONL)
hooks/guard.py                 PreToolUse allow/ask/deny
hie/                           hidden-instructions eval (simulated sandbox, deterministic grading)
hooks/stop_check.py            Stop hook: no unverified success claims
hooks/hooks.json               plugin hook wiring
commands/                      /agentscan, /audit-session
action.yml                     composite GitHub Action
action/agentscan-action.yml    example workflow
docs/REPORT-v0.1.md            the study
tests/                         unit tests (fake keys built at runtime, none committed)
```

## Not in this repo yet

The study's `data/`, `analysis/` and `charts/` are not on this machine yet. The study's numbers can't be reproduced from this repo until they're added.

## Ethics

Public data only. No credential is used or validated, and none is ever printed (redaction is covered by tests). Leaked-key locations from the study are kept outside this repo for a responsible-disclosure decision.
