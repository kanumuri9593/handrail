#!/usr/bin/env node
// Thin launcher: the rules are plain Python 3.10+ (standard library only), bundled in ../py.
"use strict";
const { spawnSync } = require("child_process");
const path = require("path");

const PY_DIR = path.join(__dirname, "..", "py");
const candidates = process.platform === "win32" ? ["py", "python", "python3"] : ["python3", "python"];

function findPython() {
  for (const cmd of candidates) {
    const args = cmd === "py" ? ["-3", "-c", "import sys;print(sys.version_info[:2]>=(3,10))"]
                              : ["-c", "import sys;print(sys.version_info[:2]>=(3,10))"];
    const r = spawnSync(cmd, args, { encoding: "utf8" });
    if (r.status === 0 && r.stdout.trim() === "True") return cmd === "py" ? ["py", "-3"] : [cmd];
  }
  return null;
}

const py = findPython();
if (!py) {
  console.error("handrail needs Python 3.10+ on PATH (macOS and most CI images already have it).\n" +
                "Install it from https://www.python.org/downloads/ or use: pipx install handrail");
  process.exit(2);
}
const env = { ...process.env, PYTHONPATH: PY_DIR + (process.env.PYTHONPATH ? path.delimiter + process.env.PYTHONPATH : "") };
const r = spawnSync(py[0], [...py.slice(1), "-m", "handrail", ...process.argv.slice(2)], { stdio: "inherit", env });
process.exit(r.status === null ? 1 : r.status);
