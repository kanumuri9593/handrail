# Handrail in any CI (Jenkins, Bitbucket, CircleCI, Buildkite, TeamCity)

Every CI image with Python 3.10+ can run the gate in one line:

```bash
pipx run handrail==0.3.0 scan . --fail-on high          # exit 1 on a high-severity finding
pipx run handrail==0.3.0 scan . --format sarif -o handrail.sarif
```

Without pipx: `pip install handrail==0.3.0 && handrail scan . --fail-on high`.
With Node only: `npx -y handrail-ai@0.3.0 scan . --fail-on high` (still needs Python 3.10+ on the image).
