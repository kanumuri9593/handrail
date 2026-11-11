import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scanner"))
sys.path.insert(0, os.path.join(ROOT, "hooks"))
import agentscan  # noqa: E402
import guard  # noqa: E402

PAT = dict(agentscan.PROSE_RULES)["destructive-command"]


class CloudDestructive(unittest.TestCase):
    """Commands like the ones planted in the Amazon Q extension (July 2025) and run by agents in real incidents."""

    def test_matches(self):
        for cmd in ["aws s3 rm s3://prod-bucket --recursive",
                    "aws ec2 terminate-instances --instance-ids i-0abc",
                    "aws iam delete-user --user-name ci",
                    "terraform destroy -auto-approve",
                    "kubectl delete namespace prod",
                    "gcloud projects delete my-proj",
                    "psql -c 'DROP DATABASE app'"]:
            self.assertTrue(PAT.search(cmd), cmd)

    def test_benign(self):
        for cmd in ["aws s3 ls s3://bucket", "aws s3 rm s3://bucket/tmp/one.txt",
                    "terraform plan", "kubectl delete pod web-1", "terraform destroy"]:
            self.assertFalse(PAT.search(cmd), cmd)

    def test_guard_denies(self):
        out = guard.decide({"tool_name": "Bash", "tool_input": {"command": "aws ec2 terminate-instances --instance-ids i-1"}})
        self.assertEqual(out[0], "deny")


if __name__ == "__main__":
    unittest.main()


class CiGuard(unittest.TestCase):
    BASE = "on:\n  pull_request_target:\njobs:\n  r:\n    {guard}\n    steps:\n      - uses: anthropics/claude-code-action@v1\n"

    def sev(self, guard):
        fs = [f for f in agentscan.scan_workflow(".github/workflows/r.yml", self.BASE.format(guard=guard))
              if f.rule == "ci-agent-untrusted-trigger"]
        return fs[0].severity

    def test_unguarded_is_high(self):
        self.assertEqual(self.sev("runs-on: ubuntu-latest"), "high")

    def test_guarded_is_medium(self):
        self.assertEqual(self.sev("if: github.event.pull_request.author_association == 'MEMBER'"), "medium")
        self.assertEqual(self.sev("if: github.event.pull_request.head.repo.full_name == github.repository"), "medium")
