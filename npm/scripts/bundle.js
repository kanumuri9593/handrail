// Copies the Python rule code into npm/py so the package is self-contained.
"use strict";
const fs = require("fs");
const path = require("path");
const root = path.join(__dirname, "..", "..");
const out = path.join(__dirname, "..", "py", "handrail");
fs.rmSync(path.join(__dirname, "..", "py"), { recursive: true, force: true });
const copy = (from, to) => {
  fs.mkdirSync(to, { recursive: true });
  for (const f of fs.readdirSync(from)) {
    if (f.endsWith(".py")) fs.copyFileSync(path.join(from, f), path.join(to, f));
  }
};
copy(path.join(root, "handrail"), out);
copy(path.join(root, "scanner"), path.join(out, "_scanner"));
copy(path.join(root, "monitor"), path.join(out, "_monitor"));
copy(path.join(root, "hooks"), path.join(out, "_hooks"));
for (const f of ["README.md", "LICENSE"]) fs.copyFileSync(path.join(root, f), path.join(__dirname, "..", f));
console.log("bundled handrail python into npm/py");
