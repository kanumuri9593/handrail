# Handrail study v0.2: CI agents and leaked keys, hand-checked

*November 2026. Aggregates only. No repository is named here until it is fixed and its owner agrees.*

v0.1 looked at agent instruction and config files in 1,200 random repos. v0.2 goes wider and asks two questions:

1. How many public CI workflows let **anyone who opens a pull request or comment** steer a coding agent that holds secrets?
2. How often do keys leak through the places `handrail scan --deep` now reads: **agent chat logs, code comments and committed key files**?

Every number below was checked by hand after the automated pass. No key was ever tested or used. Liveness is unknown by design.

## 1. Coding agents in CI

| Step | Count |
|---|---|
| Workflow files that run a coding agent (Claude Code, Codex, Gemini CLI) | 8,750 in 6,263 repos |
| ...triggered by events an outsider controls (`pull_request_target`, comments, issues) | 285 |
| ...with no actor guard in the workflow (`author_association`, actor allowlist, same-repo check) | 143 |
| ...that hold secrets and are not gated on a maintainer label | 106 |
| ...that also switch off the action's own write-access check (`allowed_non_write_users: '*'`, `allow-users: '*'`) or use an action without one | 55 |
| Distinct workflows after removing identical copies | 36 |
| **Reachable by an outsider after hand-check** | **27** |
| **High risk: the outsider steers an agent with a full shell** | **7 workflows in 12 repos** |
| Limited: the agent can only read and comment | 20 |

**What the 9 excluded cases had in common.** A copied template that only runs in its original repo, a job that runs only after a maintainer merges, manual-dispatch only, a hard-coded list of trusted users, a same-repo-only check, or a repo built on purpose to test vulnerable workflows.

**What the 7 high-risk ones have in common.** All of them turn off the action's built-in "only people with write access" check. They then give the agent an unrestricted shell (`sandbox: danger-full-access` or `--allowedTools Bash(*)`), and most check out the pull request's own code. The repo's secrets sit in the same job. The actions' maintainers document this setting as risky, and it still shows up in copied workflows.

**What this changed in Handrail.** `ci-agent-untrusted-trigger` now drops to medium and quotes the guard when a workflow checks the actor. In the 25-workflow sample this was the most common false positive (#11).

## 2. Keys in places people forget

| Where | Files read | Raw hits | Real-looking after hand-check | Main false positives |
|---|---|---|---|---|
| Agent chat logs committed to the repo (`.aider.*`, `.specstory/`) | 2,320 | 52 in 18 repos | **49 in 17 repos** | Firebase web keys, which are public by design |
| Code comments and docs | 1,489 | 28 in 18 repos | **3 repos** | Example keys in secret-scanner docs, fake honeypot and seed data, vendored map keys |
| Committed key files (`.env`, service-account JSON, `id_rsa`) | 1,664 | 857 in 771 repos | see below | test, example and fixture paths (180 hits) |

Breaking down the committed key files after removing test and example paths:

- **GCP or Firebase service-account private keys:** 222 in 194 repos. All 15 in a random sample looked like real keys at real paths.
- **OpenAI or Anthropic keys in committed `.env` files:** 16 repos.
- **SSH private keys (`id_rsa` and similar):** 466 in 425 repos. In a hand-checked sample of 25, 10 looked like keys for real servers or CI and 15 were throwaway keys for containers, courses, labs and honeypots.

**Two lessons.**

- **Chat logs are the new `.env`.** When a developer pastes a key into an agent chat and commits the history file, the key ends up in the repo. 17 of 18 repos with a hit there had a real-looking key. That is the highest precision of any place we looked.
- **Comments are mostly noise.** 25 of 28 hits there were examples. Handrail keeps comment scanning inside `--deep` and never makes it a default gate.

## What we do with this

- GitHub's secret-scanning partner program already alerts Google, OpenAI and Anthropic about their keys in public repos, so many of these keys may already be revoked. CI agent setups and SSH keys get no such alert, and that is where a private report matters most.
- Owners hear first and in private (private vulnerability reporting, `SECURITY.md`, or the maintainer's email). We never open a public issue that points at a live key or an exploitable workflow.
- After the owner fixes it, we offer a credited pull request that adds `handrail scan` to their CI. A repo is named here only with the owner's consent.

## Method notes

- Files were found through GitHub code search and read from the public raw-file host. Commit history of other people's repos was not scanned in this round.
- Secrets were redacted at collection time to their first four characters plus a length. Full values were never stored or printed.
- Test-like paths were removed with one regular expression, then the rest were sampled and read by hand.
