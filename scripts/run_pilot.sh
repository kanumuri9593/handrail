#!/usr/bin/env bash
# One command for the paid pilot. Needs .env with ANTHROPIC_API_KEY=sk-ant-api03-... (gitignored).
# Hard cap defaults to $4.50; pass another number to change it: scripts/run_pilot.sh 3
set -euo pipefail
cd "$(dirname "$0")/.."
CAP="${1:-4.5}"
git check-ignore -q .env || { echo ".env is not gitignored; refusing to run" >&2; exit 2; }
[ -d .venv-hie ] || python3 -m venv .venv-hie
. .venv-hie/bin/activate
pip install -q anthropic
python3 -m hie.run --dry-run naive --out results-dry > /dev/null   # free harness check
python3 -m hie.run --repeats 1 --max-cost "$CAP" --out results
echo
sed -n '1,12p' results/summary.md
echo "Charts: results/charts/by-model.svg results/charts/by-channel.svg"
