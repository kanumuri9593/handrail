---
description: Scan this repo's agent instruction and MCP/config files for dangerous setups
---

Run the agentscan scanner on the current project and summarize the results.

1. Run: `python3 "${CLAUDE_PLUGIN_ROOT}/scanner/agentscan.py" . --min-severity medium`
2. For each high or medium finding, open the file at that line and confirm whether it is a real risk or a false positive. A pattern match is a hypothesis, not a finding.
3. Report: confirmed risks first (file:line, what it allows, the one-line fix), then false positives you set aside and why.
4. Never print secret values. The scanner redacts them; keep them redacted.
5. Do not change any file unless the user asks.
