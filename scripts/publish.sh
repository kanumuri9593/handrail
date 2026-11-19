#!/usr/bin/env bash
# Publish Handrail to npm (handrail-ai) and PyPI (handrail) from a clean checkout of main.
# Interactive on purpose: npm login opens your browser, and PyPI asks for a token you paste (it is never stored).
set -euo pipefail
cd "$(dirname "$0")/.."

git checkout main && git pull --ff-only
python3 -m unittest discover -s tests -q
VERSION=$(python3 -c "import tomllib,sys;print(tomllib.load(open('pyproject.toml','rb'))['project']['version'])" 2>/dev/null || grep -m1 '^version' pyproject.toml | cut -d'"' -f2)
echo "Publishing Handrail $VERSION"

# --- npm -------------------------------------------------------------
if [ "$(curl -s -o /dev/null -w '%{http_code}' https://registry.npmjs.org/handrail-ai/$VERSION)" = "200" ]; then
  echo "npm: handrail-ai@$VERSION is already published"
else
  (cd npm && { npm whoami >/dev/null 2>&1 || npm login --auth-type=web; } && npm publish --access public)
fi

# --- PyPI ------------------------------------------------------------
if [ "$(curl -s -o /dev/null -w '%{http_code}' https://pypi.org/pypi/handrail/$VERSION/json)" = "200" ]; then
  echo "PyPI: handrail $VERSION is already published"
else
  rm -rf dist build *.egg-info
  uv build
  echo
  echo "PyPI needs an API token. Opening https://pypi.org/manage/account/token/ (sign up first if you have no account)."
  echo "Create a token with scope 'Entire account' (only needed for this first upload), copy it, and paste it below."
  open "https://pypi.org/manage/account/token/" 2>/dev/null || true
  read -r -s -p "PyPI token (starts with pypi-): " PYPI_TOKEN; echo
  uv publish --token "$PYPI_TOKEN" dist/*
  unset PYPI_TOKEN
  rm -rf build *.egg-info
fi

echo
echo "Done. Check: https://www.npmjs.com/package/handrail-ai  and  https://pypi.org/project/handrail/"
