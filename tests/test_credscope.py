import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from credscope.cli import main
from credscope.core import inventory, runbook, to_markdown

SECRET = "npm_SUPERSECRETVALUE123"


def home(files):
    root = Path(tempfile.mkdtemp())
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    return root


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Inventory(unittest.TestCase):
    def provs(self, items):
        return sorted({i["provider"] for i in items})

    def test_npmrc_with_token(self):
        h = home({".npmrc": f"//registry.npmjs.org/:_authToken={SECRET}\n"})
        self.assertEqual(self.provs(inventory(h, env={})), ["npm"])

    def test_npmrc_without_token_ignored(self):
        h = home({".npmrc": "save-exact=true\n"})
        self.assertEqual(inventory(h, env={}), [])

    def test_many_providers(self):
        h = home({".aws/credentials": "[default]\naws_access_key_id=AKIA\n", ".kube/config": "users:\n- user:\n    token: abc\n",
                  ".docker/config.json": '{"auths":{"ghcr.io":{"auth":"eA=="}}}', ".config/gh/hosts.yml": "github.com:\n  oauth_token: x\n",
                  ".git-credentials": "https://u:t@github.com\n", ".vault-token": "s.x", ".pypirc": "[pypi]\npassword = pypi-x\n"})
        self.assertEqual(self.provs(inventory(h, env={})), ["aws", "docker", "git", "github", "kubernetes", "pypi", "vault"])

    def test_ssh_private_key_only(self):
        h = home({".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n", ".ssh/id_ed25519.pub": "ssh-ed25519 AAA", ".ssh/known_hosts": "x"})
        items = inventory(h, env={})
        self.assertEqual([Path(i["where"]).name for i in items], ["id_ed25519"])

    def test_env_names_mapped(self):
        env = {"GITHUB_TOKEN": "x", "AWS_SECRET_ACCESS_KEY": "y", "OPENAI_API_KEY": "z", "PATH": "/bin", "AWS_REGION": "us-east-1", "SSH_AUTH_SOCK": "/s"}
        items = inventory(home({}), env=env)
        self.assertEqual({i["where"]: i["provider"] for i in items}, {"$AWS_SECRET_ACCESS_KEY": "aws", "$GITHUB_TOKEN": "github", "$OPENAI_API_KEY": "envvar"})

    def test_dotenv_in_projects(self):
        proj = home({"app/.env": "KEY=1", "app/.env.example": "KEY=", "app/node_modules/x/.env": "K=1", "svc/.env.production": "K=2"})
        items = inventory(home({}), env={}, projects=[proj])
        self.assertEqual(sorted(Path(i["where"]).name for i in items), [".env", ".env.production"])

    def test_runbook_groups_and_order(self):
        items = [{"provider": "ssh", "kind": "file", "where": "a"}, {"provider": "npm", "kind": "file", "where": "b"}, {"provider": "npm", "kind": "env", "where": "$NPM_TOKEN"}]
        book = runbook(items)
        self.assertEqual([s["provider"] for s in book], ["npm", "ssh"])
        self.assertEqual(book[0]["found"], ["b", "$NPM_TOKEN"])

    def test_markdown_checklist(self):
        md = to_markdown(runbook([{"provider": "github", "kind": "env", "where": "$GH_TOKEN"}]))
        self.assertIn("- [ ] `$GH_TOKEN`", md)
        self.assertIn("github.com/settings/tokens", md)

    def test_empty_markdown(self):
        self.assertIn("No known credential", to_markdown([]))


class Cli(unittest.TestCase):
    def test_help(self):
        code, out, _ = run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("rotation runbook", out)

    def test_never_prints_values(self):
        h = home({".npmrc": f"//r/:_authToken={SECRET}\n", ".aws/credentials": f"aws_access_key_id={SECRET}\n"})
        for fmt in ("text", "md", "json"):
            code, out, _ = run(["--home", str(h), "--no-env", "--format", fmt])
            self.assertEqual(code, 1)
            self.assertNotIn(SECRET, out)

    def test_json_shape(self):
        h = home({".vault-token": "s.x"})
        code, out, _ = run(["--home", str(h), "--no-env", "--format", "json"])
        self.assertEqual(json.loads(out)["runbook"][0]["provider"], "vault")

    def test_clean_exit_zero(self):
        self.assertEqual(run(["--home", str(home({})), "--no-env"])[0], 0)

    def test_output_file(self):
        o = Path(tempfile.mkdtemp()) / "rb.md"
        code, out, _ = run(["--home", str(home({".vault-token": "s"})), "--no-env", "--format", "md", "-o", str(o)])
        self.assertIn("Vault", o.read_text())
        self.assertIn("1 location", out)

    def test_bad_home(self):
        self.assertEqual(run(["--home", "/nope/nope"])[0], 2)


if __name__ == "__main__":
    unittest.main()
