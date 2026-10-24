# credscope

**"Rotate everything reachable from the host" — credscope tells you what that actually was.** Run it on a dev machine or CI runner after a worm or supply-chain hit and get a checklist of every credential location it found (npm, GitHub, git, AWS, GCP, Azure, Kubernetes, Docker, SSH, PyPI, Vault, `.env` files, secret-named env vars), with revoke steps and docs per provider. **It never prints secret values**, so the runbook is safe to paste into a ticket.

[![CI](https://github.com/ArisRhiannon/credscope/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/credscope/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python >= 3.9](https://img.shields.io/badge/python-%3E%3D3.9-blue)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Offline](https://img.shields.io/badge/network-none-informational)

```bash
pipx run --spec git+https://github.com/ArisRhiannon/credscope credscope --projects ~/code --format md -o rotation.md
```

## Why

Advisories for Shai-Hulud, ChainDrop and the TeamPCP litellm compromise all say the same thing: the payload ran as you, so assume every token it could read is gone. Responders then have to remember where a dozen CLIs keep their credentials. credscope is that list, as code. It is the natural next step after a [wormsweep](https://github.com/ArisRhiannon/wormsweep) hit.

## Usage

```bash
credscope                                  # quick text summary for your home dir + env var names
credscope --format md -o rotation.md       # Markdown checklist runbook
credscope --format json                    # machine-readable
credscope --projects ~/code ~/work         # also find .env files and project .npmrc tokens
credscope --home /mnt/suspect/home/alice --no-env   # inspect a mounted disk image, ignore this shell's env
```

Example Markdown (illustrative, shortened):

```markdown
## 1. npm registry token (`npm`)

- [ ] `/home/alice/.npmrc`
- [ ] `$NPM_TOKEN`

**Rotate:** Revoke all tokens at https://www.npmjs.com/settings/~/tokens ...
```

Exit codes: `0` nothing found, `1` credential locations found, `2` usage error.

## What it checks

| Provider | Locations |
|---|---|
| npm | `~/.npmrc` with `_authToken`, `~/.yarnrc.yml` with `npmAuthToken`, project `.npmrc` tokens, `NPM_*` / `NODE_AUTH_TOKEN` |
| GitHub / git | `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.config/git/credentials`, `GH_*` / `GITHUB_*` |
| AWS | `~/.aws/credentials`, `~/.aws/sso/cache`, `AWS_*` secrets |
| GCP / Azure | gcloud ADC and credential DB, Azure MSAL token cache |
| Kubernetes | `~/.kube/config` with tokens, client keys or exec plugins |
| Docker | `~/.docker/config.json` with `auth`, credential stores or helpers |
| SSH | private keys in `~/.ssh` (detected by PEM header; public keys ignored) |
| PyPI, Vault, others | `~/.pypirc`, `~/.vault-token`, `~/.netrc`, doctl, Terraform Cloud |
| `.env` | `.env`, `.env.*` under `--projects` (skips `*.example`, `node_modules`, `.git`) |

Env vars are matched **by name only** (`TOKEN`, `SECRET`, `API_KEY`, ...); values are never read into the output.

## Comparison

- [trufflehog](https://github.com/trufflesecurity/trufflehog) and similar scanners find secret *values* in code and history; credscope finds credential *locations* on a host and tells you how to revoke each.
- Commercial fleet tools (e.g. StepSecurity Dev Machine Guard) inventory credentials across many machines. credscope is a single-host, open-source, no-account CLI.

## Limits

- It knows common default paths only. Custom `AWS_SHARED_CREDENTIALS_FILE`, `KUBECONFIG` paths, OS keychains, password managers and browser sessions are not inspected (macOS Keychain / Windows Credential Manager entries are invisible to it).
- Finding a file does not mean the credential is still valid, and not finding one does not mean nothing leaked.
- CI provider secrets that were only in memory during a job are out of scope; rotate those from the CI settings.

## Related

[wormsweep](https://github.com/ArisRhiannon/wormsweep) (IOC sweep) · [lockgate](https://github.com/ArisRhiannon/lockgate) · [trapdiff](https://github.com/ArisRhiannon/trapdiff)

## License

[MIT](LICENSE)
