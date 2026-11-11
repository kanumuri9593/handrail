import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scanner"))
import agentscan  # noqa: E402
import deepscan  # noqa: E402

AWS = "AKIAQ3EGRJ7XYZ12AB34"
GH = "ghp_Zx8Cv6Bn4Mq2Wr0Ty8Ui6Op4As2Df0Gh8Jk6"


def git(cwd, *args):
    subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True)


class DeepScan(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        git(self.d, "init", "-q")
        git(self.d, "config", "user.email", "t@t")
        git(self.d, "config", "user.name", "t")
        os.makedirs(os.path.join(self.d, "src"))
        self.write("src/app.py", f'KEY = "{AWS}"\nrequests.get(u, verify=False)\npassword = "hunter2hunter2"\n')
        self.write(".aider.chat.history.md", f"pasted {GH}\n")
        self.write(".env.example", "OPENAI_API_KEY=your-key-here\n")
        git(self.d, "add", "-A")
        git(self.d, "commit", "-qm", "init")
        self.write("src/app.py", "requests.get(u, verify=False)\npassword = \"hunter2hunter2\"\n")
        git(self.d, "commit", "-qam", "remove api key")

    def write(self, rel, text):
        with open(os.path.join(self.d, rel), "w") as fh:
            fh.write(text)

    def test_all_files(self):
        rules = {(f.rule, f.path) for f in deepscan.scan_all_files(self.d).findings}
        self.assertIn(("leaked-secret", ".aider.chat.history.md"), rules)
        self.assertIn(("agent-history-committed", ".aider.chat.history.md"), rules)
        self.assertIn(("tls-verify-off", os.path.join("src", "app.py")), rules)
        self.assertIn(("hardcoded-credential", os.path.join("src", "app.py")), rules)
        self.assertNotIn("committed-env-file", {r for r, _ in rules})  # .env.example is fine

    def test_history_finds_deleted_key_once(self):
        h = deepscan.scan_history(self.d, current_values=deepscan.current_secret_fps(self.d))
        found = [f for f in h.findings if f.rule == "secret-in-history"]
        self.assertEqual(len(found), 1)  # the AWS key; the GH token is still in the tree, so the file scan reports it
        self.assertIn('remove api key', found[0].message)
        self.assertNotIn(AWS, found[0].evidence + found[0].message)

    def test_env_file(self):
        self.write(".env", "STRIPE_SECRET_KEY=sk_live_abcdefghijklmnopqrstuv\n")
        rules = {f.rule for f in deepscan.scan_all_files(self.d).findings}
        self.assertIn("committed-env-file", rules)

    def test_firebase_client_key_is_info(self):
        self.write("google-services.json", '{"api_key": [{"current_key": "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"}]}')
        fs = [f for f in deepscan.scan_all_files(self.d).findings if f.path == "google-services.json"]
        self.assertTrue(fs and all(f.severity == "info" for f in fs))

    def test_tls_defensive_not_flagged(self):
        self.assertEqual([f for f in deepscan.hygiene("a.py", "# never use verify=False\n") if f.rule == "tls-verify-off"], [])


if __name__ == "__main__":
    unittest.main()
