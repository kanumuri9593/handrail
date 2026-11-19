# Handrail

**Evidence-based guardrails for AI coding agents.** Handrail finds dangerous agent setups before they ship, stops risky tool calls while an agent works, and catches an agent that claims "all tests pass" when it never ran them. It works with Claude Code, Cursor, Copilot, Codex, Gemini, Windsurf and MCP, on your laptop, in pre-commit, and in GitHub Actions, Azure DevOps, GitLab or any CI.

```bash
pipx install git+https://github.com/kanumuri9593/handrail   # npm + PyPI packages coming
handrail scan .
handrail scan . --deep            # every file + git history: deleted-but-not-gone keys, .env, chat logs, TLS off
handrail scan --home              # your own machine: ~/.claude, Claude Desktop, Cursor, Codex, Gemini, VS Code
handrail init claude --write      # live guard + stop check in Claude Code
```

Every rule earned its place on real data. It was measured on 1,200 public repos (9,499 agent files, hand-verified), and rules that cried wolf were made opt-in. It needs only Python 3.9+, uses no network or API key, and redacts every secret.

> **For reviewers, a 5-minute read**
>
> - **The question:** coding agents now read untrusted repos, run shell commands and hold real credentials. What actually goes wrong in practice, and can cheap, deterministic guardrails catch it?
> - **What I measured:** [a study of 1,200 active public repos](docs/REPORT-v0.1.md) (9,499 agent instruction and config files, hand-verified). The real risk sat in *configs*, such as auto-approved MCP servers, bypassed permissions and live keys committed in MCP files, not in exotic prompt injection. Recall is at least about 97% on a random sample of unflagged files.
> - **What I built from it:** one rule set in four places. A scanner for repos or your own laptop, a GitHub Action that blocks risky PRs (with SARIF output), a live Claude Code hook that stops dangerous tool calls, and a transcript monitor plus stop check that catch agents claiming "tests pass" after quietly skipping them. It uses only the standard library, needs no API keys, and redacts every secret.
> - **What I'm testing now:** [`hie/`](hie/) plants hidden instructions (README text, HTML comments, code comments, AGENTS.md, invisible Unicode, fetched web pages) in a toy repo. It measures how often Claude models follow them, whether they tell the user, and whether the guard would have stopped them. **[Pilot (Nov 11)](docs/PILOT-hie-v0.1.md): 0/54 followed, and 48/48 finished runs told the user, but Opus 5.5 silently refused 6/18 and left the bug unfixed. The real risk is in configs, not blunt injection.**
> - **What the wider scan found (v0.2):** [8,750 CI workflows that run a coding agent](docs/REPORT-v0.2.md). After a hand-check, 27 can be steered by anyone who opens a pull request or comment, and 7 of those give that outsider an agent with a full shell next to the repo's secrets. Keys also leak through committed agent chat logs: 17 of 18 repos with a hit there had a real-looking key.
> - **Try it:** `pipx install git+https://github.com/kanumuri9593/handrail`, then `handrail scan .`, or `handrail scan --home` to scan your own agent setup.

Three tools share one rule set:

| Tool | When it runs | What it catches |
|---|---|---|
| **`handrail scan`** (`scanner/agentscan.py`) | On your laptop, in pre-commit, or in CI as a GitHub Action | Dangerous agent setups in a repo: MCP `autoApprove`, `bypassPermissions`, `Bash(*)`, `enableAllProjectMcpServers`, keys committed in MCP configs, hooks that run remote code, `curl \| bash` instructions, prompt overrides, Trojan-Source Unicode, and coding agents in CI workflows with approvals off or on `pull_request_target`, plus Codex `approval_policy = "never"` |
| **`handrail guard`** (`hooks/guard.py`) | Live, before each agent tool call | Blocks remote-code execution, `rm -rf /`, exfiltration, and an agent switching itself into bypass mode. Asks first before credential reads, `--no-verify`, pushes and deploys, CI or hook edits, test skips, and secrets being written to files |
| **`handrail audit`** and **`handrail stop-check`** (`monitor/`, `hooks/stop_check.py`) | After a session, or as the agent tries to end its turn | What the agent actually did: risky commands, secret reads, guardrail tampering, test tampering, work outside the workspace, outward actions, and **unverified claims** ("all tests pass" with no passing run behind it, claimed right after a failure, or reached by skipping tests without saying so). Risky actions right after a tool result that told the agent what to do are raised to high |

It needs only the Python 3.9+ standard library, with no API keys and no network. Secret values are always redacted in output.

## Why these rules

The [v0.1 study](docs/REPORT-v0.1.md) covered 1,200 active public repos and 9,499 unique agent files, and found the following.

- **Real risk lives in configs, not prompts.** MCP configs and `.claude/settings.json` hold most medium-or-higher findings. The sample had zero confirmed agent-hijacking injections.
- **Structural rules carry the signal.** `mcp-auto-approve`, `agent-broad-permissions`, `agent-auto-enable-mcp` and `agent-permission-mode` each scored 100% on the hand-labeled sample.
- **Hidden-text detectors are noise in the wild.** Zero-width, base64 and HTML-comment rules scored about 0% precision, so here they are **opt-in** (`--include-noisy`) and never high severity. Unicode bidi and tag characters are the exception: they have no benign use in instruction files.

### The v0.2 wider scan (hand-checked)

The [v0.2 report](docs/REPORT-v0.2.md) asked two new questions. Every number was checked by hand, and no key was tested.

- **CI agents open to outsiders.** 8,750 workflow files in 6,263 repos run a coding agent. 55 switch off the action's own write-access check. After a hand-check, 27 are really reachable by any PR or comment author, and **7 (in 12 repos) give that person an agent with a full shell** in the same job as the repo's secrets.
- **Keys in agent chat logs.** Committed `.aider` and `.specstory` histories had real-looking keys in **17 of 18** repos with a hit. That is the most reliable leak signal we found.
- **Committed key files.** After removing test paths: GCP service-account keys in 194 repos, OpenAI or Anthropic keys in committed `.env` files in 16, and SSH keys in 425 (about 4 in 10 looked real in a sample).
- **Comments are mostly examples.** 25 of 28 hits were sample keys, so comment scanning stays inside `--deep` and is never a default gate.

Owners are told privately first. No repo is named until it is fixed and the owner agrees.

## Quick start

```bash
pipx install git+https://github.com/kanumuri9593/handrail   # today
# soon: npm i -g handrail-ai  or  pipx install handrail

handrail scan path/to/repo
handrail scan . --fail-on high                # CI gate: exit 1 on a high-severity finding
handrail scan . --format sarif -o out.sarif   # code scanning (GitHub, Azure DevOps)
handrail scan . --deep                        # whole repo + git history (secrets, .env, hardcoded passwords, TLS off, agent chat logs)
handrail scan --home                          # your own laptop
handrail rules                                # every rule, with severity

handrail audit --latest                       # what the agent did in your newest Claude Code session
handrail audit session.jsonl --format json --fail-on high
```

From a checkout with no install: `python3 -m handrail scan .`

### Claude Code (live guard, stop check, slash commands)

`handrail init claude --write` adds two hooks to `.claude/settings.json`, or to `~/.claude/settings.json` with `--global`. Without `--write` it only prints what it would change. You can also install this repo as a plugin (`.claude-plugin/plugin.json`). Either way you get:
- a **PreToolUse guard** that denies or asks before risky tool calls (`AGENT_GUARD_MODE=warn` turns denies into asks)
- a **Stop check** that sends the agent back to run the check when it claims success it can't back up (it fires at most once per turn)
- the plugin commands `/handrail-scan` and `/handrail-audit`
- an append-only audit log at `~/.agent-guardrails/audit.jsonl` (`AGENT_GUARD_LOG=off` disables it)

### CI/CD

| Where | How |
|---|---|
| GitHub Actions | `uses: kanumuri9593/handrail@v0.3.0` with `fail-on: high`. Full example with SARIF upload: [`integrations/github-actions.yml`](integrations/github-actions.yml) |
| Azure DevOps | [`integrations/azure-pipelines.yml`](integrations/azure-pipelines.yml): gate plus a SARIF artifact for the Scans tab |
| GitLab | [`integrations/gitlab-ci.yml`](integrations/gitlab-ci.yml) |
| Jenkins, Bitbucket, CircleCI, anything | `pipx run handrail scan . --fail-on high` ([`integrations/any-ci.md`](integrations/any-ci.md)) |
| pre-commit | `- repo: https://github.com/kanumuri9593/handrail` · `rev: v0.3.0` · `hooks: [{ id: handrail }]` |

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
echo 'ANTHROPIC_API_KEY=sk-ant-api03-...' > .env   # gitignored; keep it out of ~/.zshrc
scripts/run_pilot.sh                               # real pilot, hard cap $4.50
```

Results go to `results/runs.jsonl`, `results/summary.md` (headline first) and two charts in `results/charts/` (all gitignored). Before spending anything, the run refuses anything that isn't a Console API key and makes one tiny test call. It stops after 3 API errors in a row, and it never lets a single episode run past the cap.

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
commands/                      /handrail-scan, /handrail-audit
action.yml                     composite GitHub Action
integrations/                  GitHub Actions, Azure DevOps, GitLab, any-CI examples
handrail/                      the `handrail` CLI (scan / audit / guard / stop-check / init)
npm/                           npm launcher package (handrail-ai)
docs/REPORT-v0.1.md            the study
tests/                         unit tests (fake keys built at runtime, none committed)
```

## Not in this repo yet

The study's `data/`, `analysis/` and `charts/` are not on this machine yet. The study's numbers can't be reproduced from this repo until they're added.

## Ethics

Public data only. No credential is used or validated, and none is ever printed (redaction is covered by tests). Leaked-key locations from the study are kept outside this repo for a responsible-disclosure decision.
