"""Inventory where credentials live on a host and build a rotation runbook. Never outputs secret values."""
from __future__ import annotations

import os
import re
from pathlib import Path

# provider -> how to revoke/rotate
PROVIDERS = {
    "npm": ("npm registry token", "Revoke all tokens at https://www.npmjs.com/settings/~/tokens (or `npm token list` / `npm token revoke <id>` from a clean machine), then review recently published versions of your packages.", "https://docs.npmjs.com/revoking-access-tokens"),
    "github": ("GitHub token / CLI session", "Revoke PATs at https://github.com/settings/tokens and fine-grained tokens at https://github.com/settings/personal-access-tokens, review https://github.com/settings/applications, and run `gh auth logout` then re-login. Check your repos for unexpected new repos, workflows or deploy keys.", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation"),
    "aws": ("AWS access keys / SSO cache", "Deactivate and delete the access keys in IAM (Security credentials), create new ones, and check CloudTrail for use of the old key IDs. For SSO, sign out all sessions.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"),
    "gcp": ("Google Cloud credentials", "Run `gcloud auth revoke --all`, delete and re-create any service-account keys found, and review the audit logs.", "https://cloud.google.com/iam/docs/keys-create-delete"),
    "azure": ("Azure CLI session / service principal", "Run `az logout`, reset secrets of any service principals used here (`az ad sp credential reset`), and revoke sessions in Entra ID.", "https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli"),
    "kubernetes": ("Kubernetes kubeconfig", "Rotate client certificates/tokens for every context in the kubeconfig, delete and re-create service-account tokens, and review cluster audit logs.", "https://kubernetes.io/docs/reference/access-authn-authz/authentication/"),
    "docker": ("Docker registry login", "Revoke the registry access tokens (Docker Hub: Account settings > Personal access tokens; GHCR: GitHub token) and run `docker logout` for each registry.", "https://docs.docker.com/security/for-developers/access-tokens/"),
    "ssh": ("SSH private key", "Generate a new key, remove the old public key from GitHub/GitLab, servers' authorized_keys and any deploy-key settings.", "https://docs.github.com/en/authentication/connecting-to-github-with-ssh/reviewing-your-ssh-keys"),
    "pypi": ("PyPI upload token", "Remove API tokens at https://pypi.org/manage/account/token/ and check recent releases of your projects. Prefer Trusted Publishing.", "https://docs.pypi.org/trusted-publishers/"),
    "git": ("Stored git HTTPS credentials", "Revoke the token stored for each host (usually a GitHub/GitLab PAT) and delete the credential file.", "https://git-scm.com/docs/git-credential-store"),
    "vault": ("HashiCorp Vault token", "Revoke with `vault token revoke -self` from a clean machine, or revoke the accessor; review audit device logs.", "https://developer.hashicorp.com/vault/docs/commands/token/revoke"),
    "dotenv": (".env file secrets", "Rotate every key in the file at its issuing service. The file name tells you where it lives, not what it unlocks; open it on a clean machine to list the keys.", ""),
    "envvar": ("Secret-looking environment variable", "Rotate the credential at its issuer and remove it from shell profiles / CI settings.", ""),
    "cloud-cli": ("Other CLI session", "Log out of the CLI and revoke the session or token in the provider's dashboard.", ""),
}

# (provider, relative path from home, optional content regex that must match for it to count)
LOCATIONS = [
    ("npm", ".npmrc", r"_authToken|_auth\s*="),
    ("npm", ".yarnrc.yml", r"npmAuthToken"),
    ("github", ".config/gh/hosts.yml", r"oauth_token|user:"),
    ("git", ".git-credentials", None),
    ("git", ".config/git/credentials", None),
    ("aws", ".aws/credentials", r"aws_access_key_id"),
    ("aws", ".aws/sso/cache", None),
    ("gcp", ".config/gcloud/application_default_credentials.json", None),
    ("gcp", ".config/gcloud/credentials.db", None),
    ("azure", ".azure/msal_token_cache.json", None),
    ("azure", ".azure/accessTokens.json", None),
    ("kubernetes", ".kube/config", r"token:|client-key-data|client-certificate-data|exec:"),
    ("docker", ".docker/config.json", r'"auth"\s*:|credsStore|credHelpers'),
    ("pypi", ".pypirc", r"password|token"),
    ("vault", ".vault-token", None),
    ("cloud-cli", ".config/doctl/config.yaml", r"access-token"),
    ("cloud-cli", ".netrc", r"password"),
    ("cloud-cli", ".terraform.d/credentials.tfrc.json", None),
    ("cloud-cli", ".config/hub", None),
]

SSH_KEY = re.compile(rb"-----BEGIN (OPENSSH|RSA|EC|DSA)? ?PRIVATE KEY-----")
ENV_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|AUTH)", re.I)
ENV_PROVIDER = [(re.compile(p), prov) for p, prov in [
    (r"^NPM_|^NODE_AUTH_TOKEN$", "npm"), (r"^(GH|GITHUB)_", "github"), (r"^AWS_", "aws"), (r"^(GOOGLE|GCP|GCLOUD)_", "gcp"),
    (r"^(AZURE|ARM)_", "azure"), (r"^KUBE", "kubernetes"), (r"^DOCKER", "docker"), (r"^(PYPI|TWINE)_", "pypi"), (r"^VAULT_", "vault")]]
ENV_IGNORE = {"GPG_AGENT_INFO", "SSH_AUTH_SOCK", "XAUTHORITY", "GITHUB_ACTIONS", "GITHUB_WORKFLOW", "GITHUB_REF", "GITHUB_SHA", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE"}
DOTENV = re.compile(r"^\.env(\..+)?$")
SKIP = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".cache", "Library", "AppData", ".npm", ".cargo", ".rustup"}


def _matches(path: Path, rx):
    if rx is None:
        return True
    try:
        return re.search(rx, path.read_text(encoding="utf-8", errors="replace")[:200_000]) is not None
    except OSError:
        return False


def inventory(home, env=None, projects=(), max_depth=4):
    home = Path(home)
    items = []
    for prov, rel, rx in LOCATIONS:
        p = home / rel
        if p.exists() and (p.is_dir() or _matches(p, rx)):
            items.append({"provider": prov, "kind": "file", "where": str(p)})
    ssh = home / ".ssh"
    if ssh.is_dir():
        for f in sorted(ssh.iterdir()):
            try:
                if f.is_file() and f.stat().st_size < 64_000 and SSH_KEY.search(f.read_bytes()[:200]):
                    items.append({"provider": "ssh", "kind": "file", "where": str(f)})
            except OSError:
                pass
    for name in sorted((env if env is not None else os.environ)):
        if name in ENV_IGNORE or not ENV_NAME.search(name):
            continue
        prov = next((pv for rx, pv in ENV_PROVIDER if rx.search(name)), "envvar")
        items.append({"provider": prov, "kind": "env", "where": "$" + name})
    for root in projects:
        root = Path(root)
        for dirpath, dirnames, filenames in os.walk(root):
            depth = len(Path(dirpath).relative_to(root).parts)
            dirnames[:] = [d for d in dirnames if d not in SKIP and depth < max_depth]
            for fn in filenames:
                if DOTENV.match(fn) and not fn.endswith((".example", ".sample", ".template")):
                    items.append({"provider": "dotenv", "kind": "file", "where": str(Path(dirpath) / fn)})
                elif fn == ".npmrc" and _matches(Path(dirpath) / fn, r"_authToken"):
                    items.append({"provider": "npm", "kind": "file", "where": str(Path(dirpath) / fn)})
    return items


def runbook(items):
    groups = {}
    for it in items:
        groups.setdefault(it["provider"], []).append(it["where"])
    order = list(PROVIDERS)
    out = []
    for prov in sorted(groups, key=order.index):
        title, steps, doc = PROVIDERS[prov]
        out.append({"provider": prov, "title": title, "found": groups[prov], "rotate": steps, "docs": doc})
    return out


def to_markdown(book, host_label="this host"):
    lines = [f"# Credential rotation runbook for {host_label}", "",
             "Generated by credscope. Lists **where** credentials were found, never their values. Do the rotation from a known-clean machine.", ""]
    if not book:
        lines += ["No known credential locations found. Check CI secrets, password managers and browser sessions separately."]
    for i, s in enumerate(book, 1):
        lines += [f"## {i}. {s['title']} (`{s['provider']}`)", ""]
        lines += [f"- [ ] `{w}`" for w in s["found"]]
        lines += ["", f"**Rotate:** {s['rotate']}"]
        if s["docs"]:
            lines += ["", f"Docs: {s['docs']}"]
        lines += [""]
    lines += ["## Afterwards", "", "- [ ] Delete the old credential files once rotated", "- [ ] Check provider audit logs for use between the suspected compromise time and rotation", ""]
    return "\n".join(lines)
