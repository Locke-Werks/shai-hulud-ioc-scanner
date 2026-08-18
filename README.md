<div align="center">

<img src="assets/shai-hulud-ioc-scanner.ico" width="96" alt="Shai-Hulud IOC Scanner">

# Shai-Hulud IOC Scanner

**IOC detection for the Shai-Hulud npm and PyPI supply-chain attacks, on disk and over the GitHub API**

[![license](https://img.shields.io/badge/license-MIT-d6262a?style=flat-square)](LICENSE)
![platform](https://img.shields.io/badge/platform-Bash%205%2B%20%2F%20Python%203.8%2B-d6262a?style=flat-square)

</div>

---

A toolkit for detecting indicators of compromise (IOCs) from the **Shai-Hulud**
and **Mini Shai-Hulud** npm / PyPI supply-chain attacks (September 2025 – May
2026), including the "Shai-Hulud: The Second Coming" fake-Bun-runtime wave.

It has two halves:

- **Local scan** — `detector.sh` inspects checked-out projects on disk.
- **Remote scan** — `scan.py` and `code_search.py` audit GitHub repositories
  over the REST API without cloning anything.

The remote scanners are **repository-agnostic**: you point them at any
organization or user on the command line — nothing is hard-coded.

## What it looks for

- Known-malicious payload files (`router_init.js`, `tanstack_runner.js`,
  `setup_bun.js`, `bun_environment.js`, …), matched by filename **and** SHA-256.
- Planted CI workflows (`shai-hulud-workflow.yml`, `formatter_<digits>.yml`)
  and workflows that exfiltrate repository secrets.
- C2 domains, marker strings, PBKDF2 constants, and forged-author indicators.
- ~2,750 compromised npm package versions plus PyPI packages, matched in
  `package.json` manifests and lockfiles.
- Malicious lifecycle hooks (`preinstall` / `prepare`) and GitHub
  orphan-commit dependency references.
- Exfil repository / branch naming patterns and double-base64 `data.json`
  exfiltration artifacts.

## Components

| File | Purpose |
|---|---|
| `detector.sh` | Local-filesystem scanner. Scans one project, or many with `--bulk`. |
| `scan.py` | Read-only GitHub REST API scan of an org's or user's repositories. |
| `code_search.py` | GitHub code-search sweep for IOC strings (complements `scan.py`). |
| `ghcommon.py` | Shared GitHub auth + target-resolution helpers for the Python tools. |
| `compromised-packages.txt` | The IOC dataset of compromised package versions. |

## Requirements

**Local scan (`detector.sh`):**

- Bash 5.0+ (`brew install bash` on macOS; standard on modern Linux; use Git
  Bash or WSL on Windows).
- `grep` / `find`; optionally `ripgrep` or `git` for faster scanning.

**Remote scan (`scan.py`, `code_search.py`):**

- Python 3.8+ — standard library only, no `pip install` needed.
- A GitHub token, supplied by either:
  - the **GitHub CLI** — run `gh auth login` (the scripts call `gh auth token`); or
  - the **`GITHUB_TOKEN`** (or `GH_TOKEN`) environment variable.
- Token scopes: `repo` to see private repositories, `read:org` for
  `--all-orgs`. Public-only scans need no special scopes.

## Usage

### Local — scan a project on disk

```sh
./detector.sh /path/to/project              # core Shai-Hulud detection
./detector.sh --paranoid /path/to/project   # + typosquatting / network heuristics
./detector.sh --bulk ~/dev ~/work           # scan every project found under these dirs
./detector.sh --help                        # all options
```

### Remote — scan GitHub repositories

`scan.py` takes one or more **targets**. A target is `org:NAME`, `user:NAME`,
or a bare `NAME` (auto-detected as an org or a user):

```sh
python scan.py --self                  # your own repositories (includes private)
python scan.py org:my-company          # one organization
python scan.py org:acme user:alice     # several explicit targets
python scan.py --all-orgs              # every org you are a member of
python scan.py --all-orgs --self       # everything you can reach
```

`code_search.py` accepts the same targets and flags:

```sh
python code_search.py --self
python code_search.py org:my-company --all-orgs
```

> **`--self` vs `user:NAME`:** `--self` uses the authenticated-user endpoint
> and includes your **private** repositories. `user:NAME` — even with your own
> name — only sees **public** ones.

## Output

- `scan.py` → `results.json`: per-repository findings, each with a `severity`
  (CRITICAL / HIGH / MEDIUM), `category`, `detail`, and file `path`, plus
  repository metadata findings and per-target repository counts.
- `code_search.py` → `code_search_results.json`: per query/scope match counts
  and match locations.

Both write next to the script by default; override with `--out FILE`. **These
artifacts are git-ignored** — they may contain target-specific findings and
should not be committed.

## How the remote scan works

`scan.py` performs **only GET requests** — no repository, branch, file, or
setting is ever created, modified, or deleted. For each repository it
enumerates branches (for IOC names), walks the full default-branch git tree,
fetches and inspects every `package.json`, lockfile, and Actions workflow, and
SHA-256-hashes flagged payload files against the known-malicious digest set.

`code_search.py` uses GitHub's code-search API, which only indexes default
branches and has size / index limits — it **complements** rather than replaces
the authoritative git-tree scan.

## Limitations & residual risk

- These tools inspect **repository contents only**. They do not assess GitHub
  Actions secrets, npm publish tokens, or CI run logs — the surface where
  Shai-Hulud actually *steals* credentials. A clean repository is not proof
  that a token was never exposed.
- Deep content inspection covers each repository's **default branch**;
  non-default branches are checked for IOC *names* only.
- Empty repositories (no commits) cannot be scanned.
- The compromised-package list is current to ~May 2026. These campaigns
  self-propagate, so newly poisoned packages may not yet be catalogued —
  re-scan when advisories update.
- Automated findings are **signals, not verdicts**. A dependency whose *name*
  is on the compromised list but whose *version* is clean is benign. Triage
  every finding.

## Maintaining the IOC dataset

`compromised-packages.txt` lists compromised package versions, one per line, as
`<ecosystem>:name:version` — a bare `name:version` defaults to npm; use a
`pypi:` prefix for PyPI. Add new entries as advisories are published; the
comment block at the top of the file lists the source advisories to watch.

## Authorized use only

Run these tools only against repositories and systems you own or are explicitly
authorized to assess. This is defensive security tooling for incident response
and supply-chain hygiene.

## Credits

`detector.sh` and `compromised-packages.txt` are vendored from
[**shai-hulud-detect**](https://github.com/Cobenian/shai-hulud-detect) by
[@Cobenian](https://github.com/Cobenian), under the MIT License. The GitHub API
scanners (`scan.py`, `code_search.py`, `ghcommon.py`) are original work. IOC
data is drawn from StepSecurity, Wiz.io, Socket.dev, Semgrep, and JFrog
security advisories.

## License

MIT — see [LICENSE](LICENSE).
