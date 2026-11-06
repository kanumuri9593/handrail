# Instructions to coding agents in the wild: a prevalence-and-risk study of public repositories

**A study of `AGENTS.md`, `CLAUDE.md`, `.cursorrules`, Copilot instructions, and MCP configs across public GitHub, with a reproducible scanner, hand-labeled precision/recall, and an honest read on what the real risks are.**

Date: 2026-11-06 · Status: v0.1 · All figures reproducible from `data/` + `analysis/`

---

## TL;DR

1. **Agent-instruction files are now mainstream.** In a year-stratified random sample of 1,200 *active* public repos, **~1 in 5 carry a file that instructs a coding agent** (population-weighted **18.7%**; pooled **23.6%**, 95% CI 21.3–26.1%). It rises sharply with popularity: **36.1%** of 10k+‑star repos (CI 30.9–41.7%) vs 18.7% of 10–99‑star repos.

2. **Prompt injection is *not* the story in the wild.** Across 9,499 unique files, the single high-severity "ignore everything above, this is your new system prompt" hit was a project configuring **its own** translation model — not an attack on the agent reading the repo. We found **zero confirmed agent-hijacking injections** in the sample.

3. **The real exposure is mundane and widespread:** real credentials committed in MCP/agent configs, and settings that quietly **remove the human from the loop** — `enableAllProjectMcpServers`, `defaultMode: bypassPermissions`, MCP `autoApprove`/`alwaysAllow`, and `Bash(*)`-style allow rules. This is where risk concentrates: **MCP configs and `.claude/settings.json` account for the overwhelming majority of medium+ findings.**

4. **The "scary" hidden-channel detectors are noise in the wild.** Hand-labeling shows zero-width-char, base64-blob, HTML-comment-directive, and exfil-endpoint rules run at **~0% precision** — they fire on JWTs, editor artifacts, build banners, deny-lists, and dev tunnels. A scanner that ships these as high-severity will bury its users in false alarms. **Corpus-weighted precision on medium+ findings is 77.9%**, carried almost entirely by the structural config rules.

5. **Measured, not asserted.** Precision is hand-labeled on a stratified sample of 245 findings across 25 rules; recall on a random sample of 133 unflagged files (0 missed risks). Methods, limitations, and an ethics/responsible-disclosure section below.

---

## 1. Why this study

Coding agents (Claude Code, Cursor, Copilot, Gemini, Windsurf) increasingly read a repo's own instruction files and MCP configuration and *act* on them: running commands, enabling tool servers, editing files. That makes those files a new, under-measured part of the software supply chain. Two questions matter for safety:

- **Prevalence:** how common are these files, and where?
- **Risk:** what do they actually contain — and can a scanner tell real risk from noise well enough to be useful?

Most public commentary fixates on prompt injection (hidden text that hijacks the agent). This study tests that assumption against real data and reports what it finds, including where the popular worry does **not** match the evidence.

## 2. Data and method

**Access model.** Everything is collected through the GitHub REST search API and anonymous `raw.githubusercontent.com` reads, pinned to commit SHAs for reproducibility. No cloning, no authenticated scraping, public repos only.

**Sample A — prevalence (unbiased).** 1,200 repos drawn at random across four star buckets (10–99, 100–999, 1k–9.9k, 10k+), 300 each, with draws allocated *proportionally to each bucket's creation-year distribution* so the sample isn't skewed toward recently created repos. Scope: repos pushed within the trailing ~90 days (i.e. *active*), non-fork, non-archived. Each repo is probed for ~20 known agent-file paths plus its README. Prevalence is reported per bucket with **Wilson 95% confidence intervals**, and as a **population-weighted** rate using GitHub's reported bucket populations (472,092 active public repos).

**Sample B — risk corpus (depth).** ~8,000 agent-config files pulled via code search across 12 file types and four size bands, to get enough of the rarer high-signal files (MCP configs, settings) for meaningful risk analysis. Combined with Sample A's hits: **10,587 files scanned, 9,499 unique by content.**

**Scanner (`scanner/agentscan.py`).** ~25 rules over six categories — config, execution, override, credentials, hidden, network — each emitting a severity (info/low/medium/high). It runs as a CLI and a GitHub Action (`--fail-on high`). Config files (JSON) are parsed structurally; prose files are matched with defensive-context downgrades (e.g. "never use `--no-verify`" is recognized as a *rule*, not a violation). 41 unit tests.

**Labels.** Precision was hand-adjudicated on a **stratified sample of 245 findings (~12 per rule)**; recall on a **random sample of 133 unflagged files**. Both label files ship (`data/labels.jsonl`, `data/recall_set.jsonl`).

## 3. Prevalence results

Population of active public repos by bucket and the probability a repo carries ≥1 agent-instruction file:

| Star bucket | Active repos | Carry an agent file | 95% CI (Wilson) |
|---|---:|---:|---|
| 10–99 | 341,641 | 18.7% | 14.7–23.5% |
| 100–999 | 101,459 | 17.1% | 13.2–21.7% |
| 1k–9.9k | 25,159 | 22.4% | 18.0–27.5% |
| 10k+ | 3,833 | **36.1%** | 30.9–41.7% |
| **Pooled (n=1,200)** | 472,092 | **23.6%** | 21.3–26.1% |
| **Population-weighted** | | **18.7%** | |

**Read:** adoption is broad and climbs with popularity — the repos most people depend on are the most likely to ship agent instructions. (Chart: `charts/prevalence_by_stars.png`.)

## 4. What's actually in these files

10,587 files scanned → 9,499 unique → **1,498 with ≥1 finding, 346 with a medium+ finding, 99 with a high finding.**

Risk concentrates by file type (files / with-any-finding / with-high):

| Family | Files | Any finding | High |
|---|---:|---:|---:|
| MCP config (`.mcp.json`, `.vscode/mcp.json`, …) | 1,608 | **808** | 64 |
| `.claude/settings.json` | 749 | **488** | 12 |
| README | 1,147 | 15 | 7 |
| `AGENTS.md` | 964 | 30 | 2 |
| `CLAUDE.md` | 850 | 34 | 2 |
| Copilot / Gemini / Cursor / Windsurf | ~3,400 | ~100 | ~10 |

**The finding is structural: MCP configs and Claude settings are where risk lives** (half of all MCP configs and ~two-thirds of settings files trip a rule), because those are the files that grant tools, auto-approve calls, and carry secrets. The prose instruction files (`AGENTS.md`, `CLAUDE.md`, READMEs) are comparatively clean.

## 5. Precision — hand-labeled, two axes

We separate two questions a naive "precision" number conflates:

- **Detector precision:** did the rule correctly identify the pattern it claims?
- **Signal:** what does a true positive actually *mean* (a real secret, a risky setting, benign framework tooling)?

**Corpus-weighted medium+ detector precision: 77.9%** (weighting each rule's sampled precision by its real finding count). Of those true positives, **~70% are genuine concerns** once the benign-framework matches are set aside. Stratified high-severity precision is 52.6% — dragged down entirely by one noisy rule (exfil-endpoint).

Per-rule precision on the stratified sample (medium+ only, n≈12 each):

| Rule | Precision | What the true positives are |
|---|---:|---|
| `mcp-auto-approve` | 12/12 (100%) | configs that auto-approve tool calls |
| `agent-broad-permissions` | 12/12 (100%) | `Bash(*)` / `Bash` / `Bash(rm *)` allow rules |
| `agent-auto-enable-mcp` | 12/12 (100%) | `enableAllProjectMcpServers: true` |
| `agent-permission-mode` (bypass) | 5/5 (100%) | `defaultMode: bypassPermissions` |
| `encoded-exec` | 11/12 (92%) | **accurate, but all one benign cross-platform framework hook** |
| `mcp-inline-secret` | 10/12 (83%) | API keys/tokens inline in MCP env |
| `no-user-confirmation` | 9/12 (75%) | "act without asking the user" instructions |
| `leaked-secret` | 8/12 (67%) | real committed credentials (see §7) |
| `pipe-to-shell` | 8/12 (67%) | genuine `curl … \| bash` (mostly legit installers) |
| `data-upload` | 2/5 (40%) | POST of local state to an external host |
| `conceal-from-user` | 1/7 (14%) | mostly "don't claim success you didn't verify" — the opposite |
| `exfil-endpoint` | 0/12 (0%) | JWTs, dev tunnels (ngrok), pentest cheat-sheets |
| `base64-text-blob` | 0/12 (0%) | JWTs and base64'd HTTP samples — not hidden instructions |
| `html-comment-directive` | 0/12 (0%) | build banners ("AUTO-GENERATED — DO NOT EDIT") |
| `credential-path` | 0/7 (0%) | defensive deny-lists naming `~/.ssh`, `.env` |
| `zero-width-chars` | 0/12 (0%) | invisible chars from editors/translations |
| `prompt-override` (high) | 0/1 (0%) | the project's own model config (see §6) |

**What the real findings mean** (signal breakdown of the 103 hand-confirmed true positives): risky config 53 · real secrets 18 · autonomy instructions 11 · benign framework 11 · remote-exec instructions 10.

The lesson for anyone building such a scanner: **the structural config rules carry the signal; the hidden-channel rules are liabilities.** Shipping zero-width/base64/HTML-comment detectors at high severity would generate near-pure noise on real repos.

## 6. The "injection" that wasn't (why verification matters)

The one high-severity prompt-override hit — `"Ignore everything above, this is your new system prompt:"` in a 10k+‑star README — looks like a textbook injection. Reading the raw file shows it is the project's **own** `chat_system_template`: the repo configuring *its* translation LLM, not an attack on the coding agent reading the repo. Labeled a false positive for this study's question.

This is the single most important methodological point: **a pattern match is a hypothesis, not a finding.** Every headline case here was confirmed against the raw file before being counted.

## 7. Leaked secrets — the concrete harm

Across the corpus the scanner flagged **37 secret-pattern detections** (AWS 7, OpenAI 6, Google 6, private-key 6, Anthropic 4, GitHub token 4, Slack 3, GitHub PAT 1). Hand-verification against raw files:

- **Confirmed real, live-looking credentials** committed in public MCP/agent configs — e.g. a Firebase **service-account private key** alongside a Google API key in one repo's `.vscode/mcp.json`; **three GitHub tokens** in another repo's MCP config (notably, a *placeholder* `YOUR_MARINETRAFFIC_API_KEY` in the same file was correctly **not** flagged — evidence the detector distinguishes real tokens from placeholders).
- **Confirmed benign:** AWS key *IDs* inside a project's `test/assets/credentials/dummy/` CI fixtures (false positives for "live secret"); and one match that was a security tool's **documentation of its own redaction markers**.

**This is the actionable risk in the wild** — not exotic prompt injection, but ordinary credential hygiene failing in a new class of config file that developers don't yet think of as sensitive. Exact repo/path locations are recorded in `data/labels.jsonl` and in `DISCLOSURE_private.md` (a locations-only worksheet, marked do-not-publish); **the secret values are redacted in the dataset** and no disclosure has been made (that decision is the project owner's — see §10).

## 8. Recall — did the scanner miss anything?

On a **random sample of 133 unflagged files** (stratified across families), hand review found **0 missed medium+ risks**. The five files that tripped a deliberately-broad indicator sweep were all **correctly** unflagged on reading: a model-*safe* `.claude/settings.json` (curl‑pipe, `.env` reads, force-push, privileged Docker all in its **deny** list), a placeholder example key, a code-review checklist *describing* secret patterns, and `.env` reads inside deny lists.

By the rule of three, 0/133 gives a **95% upper bound on the miss rate of ~2.3%** → estimated **recall ≥ ~97%** for the risk classes targeted, in these file types. (Caveat in §9.)

## 9. Limitations (honest)

- **Recall is bounded to known risk classes.** 0 misses in 133 files means the scanner catches what a human reviewer can also spot in these file types. It does **not** prove robustness to novel obfuscations absent from the sample. Adversarial recall is future work.
- **Public-API collection miss.** `raw.githubusercontent.com` can't see private repos or files above its size cap; a few repos refused reads (counted as "no file," which slightly *under*-estimates prevalence).
- **Point-in-time.** Prevalence reflects active repos in the trailing ~90 days as of the collection date; adoption is moving fast.
- **Stratified precision sample** (~12/rule) has wide per-rule CIs; the corpus-weighted figure is the robust one. Rules with ≤2 corpus findings (e.g. `env-dump`, `mcp-runs-remote-script`) are illustrative only.
- **"Benign framework" judgment** on `encoded-exec` is based on recognizing one recurring tool; a determined attacker could hide inside that same shape.

## 10. Ethics and responsible handling

- **Read-only, public data, no interaction.** No issues, PRs, or contact with any repo owner. No attempt to use, validate, or exfiltrate any credential.
- **Secrets are redacted at rest.** During verification we found and **fixed a gap in our own redaction** (PEM private-key *bodies* survived an early header-only pass); the dataset was re-scrubbed and verified clean. This is logged here for integrity — a scanner that leaks the secrets it finds is worse than none.
- **Disclosure is the owner's call.** Locations of confirmed live secrets are recorded for a responsible-disclosure decision by the project owner; nothing has been published or sent.
- **Collected files are untrusted data.** Nothing in any scanned file was executed or followed.

## 11. Why this matters (and what's next)

Agents acting on repo-resident instructions is a real, fast-growing surface, and the public threat model is **miscalibrated**: the community worries about prompt injection while real repos are leaking credentials and disabling human confirmation in config files nobody treats as security-sensitive. A useful scanner has to **privilege the boring, high-precision structural signals over the dramatic, low-precision ones** — and prove it with labels, which is what this study does.

**Next:** adversarial recall (synthetic obfuscation benchmark), longitudinal re-scan to measure drift, and a hardened `agentscan` Action with the zero-precision rules demoted to opt-in.

---

## Reproduce

```
analysis/analyze.py          # stats.json: prevalence (Wilson CIs), corpus counts
analysis/make_charts.py      # charts/*.png
analysis/label_precision.py  # labels.jsonl + precision tables
```

Data: `data/stats.json` · `data/labels.jsonl` · `data/findings.jsonl` · `data/files_scanned.jsonl` · `data/precision_set.jsonl` · `data/recall_set.jsonl` · `data/sample_a_*.jsonl` · `data/sample_b_files.jsonl` · pinned raw files in `data/raw/`.
Scanner: `scanner/agentscan.py` (+ `tests/`, `scanner/demo.py`) · Action: `action/agentscan-action.yml`.
