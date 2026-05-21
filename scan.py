#!/usr/bin/env python3
"""Shai-Hulud / Mini Shai-Hulud IOC scanner.

Read-only GitHub REST API scan of repositories belonging to any organization
or user. Targets are supplied on the command line (org:NAME / user:NAME), via
--self, or via --all-orgs; nothing is hard-coded. Performs only GET requests —
no repository, branch, file, or setting is ever modified.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import ghcommon

WORK = os.path.dirname(os.path.abspath(__file__))
NotFound = ghcommon.NotFound
HDR = None  # request headers, populated in main()

# ---------------------------------------------------------------- IOC DATA
# Known-malicious SHA-256 hashes of payload files (Shai-Hulud family + Mini Shai-Hulud)
IOC_HASHES = {
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",  # router_init.js
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96",  # tanstack_runner.js
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b",  # malicious package.json
    "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c",  # atool/AntV payload
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a",  # setup_bun.js
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",  # bun_environment.js
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",  # bun_environment.js
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",  # bun_environment.js
}
# Payload filenames (exact basename). bundle.js handled separately (hash-only).
IOC_PAYLOAD_FILES = {
    "setup_bun.js", "bun_installer.js", "bun_environment.js", "environment_source.js",
    "router_init.js", "tanstack_runner.js", "kitty-monitor.sh", "kitty-monitor.service",
    "gh-token-monitor.sh", "gh-token-monitor.service", "actionsSecrets.json",
    "com.user.kitty-monitor.plist", "com.user.gh-token-monitor.plist",
}
# Content-string IOCs (substring match in fetched file content)
IOC_STRINGS = {
    "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner": "wipe-threat token description",
    "A Mini Shai-Hulud has Appeared": "Mini Shai-Hulud May-11 marker string",
    "niagA oG eW ereH :duluH-iahS": "Mini Shai-Hulud May-19 beacon string (reversed)",
    "siridar-ghola-567": "Mini Shai-Hulud exfil repo name",
    "tleilaxu-ornithopter-43": "Mini Shai-Hulud exfil repo name",
    "voicproducoes": "Mini Shai-Hulud threat actor (May-11)",
    '"_npmUser":{"name":"atool"': "Mini Shai-Hulud threat actor atool (May-19)",
    "huiyu.zjt@ant.com": "Mini Shai-Hulud forged-author email",
    "firedalazer": "Mini Shai-Hulud C2 dead-drop keyword",
    "0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa": "Mini Shai-Hulud PBKDF2 master key constant",
    "svksjrhjkcejg": "Mini Shai-Hulud PBKDF2 salt constant",
    "api.masscan.cloud": "Mini Shai-Hulud C2 domain",
    "git-tanstack.com": "Mini Shai-Hulud C2 domain",
    "filev2.getsession.org": "Mini Shai-Hulud C2 domain",
    "seed1.getsession.org": "Mini Shai-Hulud C2 domain",
    "t.m-kosche.com": "Mini Shai-Hulud C2 domain",
    "79ac49eedf774dd4b0cfa308722bc463cfe5885c": "Mini Shai-Hulud malicious commit SHA",
    "1916faa365f2788b6e193514872d51a242876569": "Mini Shai-Hulud malicious commit SHA",
    "7cb42f57561c321ecb09b4552802ae0ac55b3a7a": "Mini Shai-Hulud malicious commit SHA",
    "dc3d62a2181beb9f326952a2d212900c94f2e13d": "Mini Shai-Hulud malicious commit SHA",
    "npmjs.help": "npm phishing domain (Shai-Hulud family)",
    "Sha1-Hulud: The Second Coming": "Shai-Hulud Second Coming marker",
}
# package.json structural IOCs (substring in manifest content)
IOC_MANIFEST = {
    "github:tanstack/router#79ac49ee": "malicious optionalDependency (tanstack/router orphan commit)",
    "github:antvis/G2#1916faa365": "malicious optionalDependency (antvis/G2 orphan commit)",
    "github:antvis/G2#7cb42f5756": "malicious optionalDependency (antvis/G2 orphan commit)",
    "github:antvis/G2#dc3d62a218": "malicious optionalDependency (antvis/G2 orphan commit)",
    '"preinstall": "bun run index.js"': "Mini Shai-Hulud preinstall install vector (May-19)",
    "bun run tanstack_runner.js": "Mini Shai-Hulud prepare-script payload invocation (May-11)",
    '"node setup_bun.js"': "Shai-Hulud fake-Bun-runtime preinstall hook",
    '"node bun_installer.js"': "Shai-Hulud fake-Bun-runtime preinstall hook",
}
IOC_WORKFLOW_NAMES = re.compile(r"(shai-hulud-workflow\.ya?ml|formatter_\d{6,}\.ya?ml)$", re.I)
# Generic suspicious workflow patterns (lower confidence -> MEDIUM)
WF_SUSPICIOUS = [
    (re.compile(r"curl\s+[^\n|]*\|\s*(bash|sh)\b"), "pipes remote download to shell"),
    (re.compile(r"wget\s+[^\n|]*\|\s*(bash|sh)\b"), "pipes remote download to shell"),
    (re.compile(r"base64\s+-d[^\n|]*\|\s*(bash|sh)\b"), "decodes base64 directly into shell"),
    (re.compile(r"toJSON\(secrets\)"), "serialises all repository secrets"),
    (re.compile(r"pull_request_target"), "pull_request_target trigger (token-exfil risk)"),
]
LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}


# ---------------------------------------------------------------- HTTP
def api(path, raw=False):
    """Authenticated GET against the GitHub API; returns (data, headers)."""
    return ghcommon.request(path, HDR, raw=raw)


def paginate(path):
    """Follow Link-header pagination for an API path."""
    return ghcommon.paginate(path, HDR)


# ---------------------------------------------------------------- IOC load
def load_compromised(path):
    npm, pypi = set(), set()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            eco = "npm"
            if line.startswith("pypi:"):
                eco, line = "pypi", line[5:]
            elif line.startswith("npm:"):
                eco, line = "npm", line[4:]
            if ":" not in line:
                continue
            name, ver = line.rsplit(":", 1)
            (npm if eco == "npm" else pypi).add((name.strip(), ver.strip()))
    return npm, pypi


NPM_BAD, PYPI_BAD = load_compromised(os.path.join(WORK, "compromised-packages.txt"))
NPM_BAD_NAMES = {n for n, _ in NPM_BAD}


# ---------------------------------------------------------------- parsers
def sha256(b):
    return hashlib.sha256(b).hexdigest()


def blob_bytes(full, sha):
    j, _ = api(f"/repos/{full}/git/blobs/{sha}")
    if j.get("encoding") == "base64":
        return base64.b64decode(j.get("content", ""))
    return j.get("content", "").encode("utf-8", "replace")


def scan_lockfile(name, text):
    """Return list of (pkg, version) found that are compromised."""
    hits = []
    pairs = []
    try:
        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            j = json.loads(text)
            for key, meta in (j.get("packages") or {}).items():
                if not key:
                    continue
                pkg = key.split("node_modules/")[-1]
                v = meta.get("version")
                if pkg and v:
                    pairs.append((pkg, v))
            def walk(d):
                for pkg, meta in (d or {}).items():
                    v = meta.get("version")
                    if v:
                        pairs.append((pkg, v))
                    walk(meta.get("dependencies"))
            walk(j.get("dependencies"))
        elif name == "yarn.lock":
            cur = []
            for ln in text.splitlines():
                if ln and not ln.startswith(" ") and not ln.startswith("#") and ln.rstrip().endswith(":"):
                    cur = []
                    for spec in ln.rstrip(":").split(","):
                        spec = spec.strip().strip('"')
                        at = spec.rfind("@")
                        if at > 0:
                            cur.append(spec[:at])
                elif ln.strip().startswith("version") and cur:
                    v = ln.split('"')[1] if '"' in ln else ln.split()[-1]
                    for c in cur:
                        pairs.append((c, v))
                    cur = []
        elif name == "pnpm-lock.yaml":
            for ln in text.splitlines():
                m = re.match(r"\s+/?(@?[^@/\s][^@\s]*?)@([0-9][^():\s]*)[:(\s]", ln)
                if m:
                    pairs.append((m.group(1), m.group(2)))
                m2 = re.match(r"\s+'?/?(@?[^@'/\s][^@'\s]*?)@([0-9][^'():\s]*)'?:", ln)
                if m2:
                    pairs.append((m2.group(1), m2.group(2)))
    except Exception as e:
        return [("__parse_error__", str(e)[:120])]
    for pkg, v in pairs:
        if (pkg, v) in NPM_BAD:
            hits.append((pkg, v))
    return hits


def scan_manifest(text):
    """Return (hook_findings, dep_name_matches, structural_findings)."""
    hooks, depnames, struct = [], [], []
    for needle, desc in IOC_MANIFEST.items():
        if needle in text:
            struct.append(desc)
    try:
        j = json.loads(text)
    except Exception:
        return hooks, depnames, struct
    scripts = j.get("scripts") or {}
    for hk in ("preinstall", "postinstall", "install", "prepare", "prepublish"):
        val = scripts.get(hk)
        if not isinstance(val, str):
            continue
        low = val.lower()
        for tok in ("setup_bun", "bun_installer", "bun_environment", "router_init",
                    "tanstack_runner", "environment_source", "cat.py", "curl ", "wget ",
                    "bun run index.js"):
            if tok in low:
                hooks.append(f"{hk}: {val[:160]}")
                break
    for sect in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for pkg, ver in (j.get(sect) or {}).items():
            if pkg in NPM_BAD_NAMES:
                depnames.append(f"{pkg}@{ver} ({sect})")
            if isinstance(ver, str) and ("github:tanstack/router#" in ver
                                         or "github:antvis/G2#" in ver):
                struct.append(f"{sect} uses GitHub orphan-commit ref: {pkg}@{ver}")
    return hooks, depnames, struct


# ---------------------------------------------------------------- per-repo scan
def scan_repo(repo):
    full = repo["full_name"]
    f = {"repo": full, "private": repo.get("private"), "fork": repo.get("fork"),
         "archived": repo.get("archived"), "findings": [], "errors": [],
         "truncated": False, "manifests": 0, "lockfiles": 0, "workflows": 0}

    def add(sev, cat, detail, path=""):
        f["findings"].append({"severity": sev, "category": cat, "detail": detail, "path": path})

    # branches
    try:
        for br in paginate(f"/repos/{full}/branches?per_page=100"):
            bn = br.get("name", "")
            if "shai-hulud" in bn.lower() or bn.lower().endswith("-migration"):
                add("HIGH", "branch", f"IOC branch name: {bn}")
    except NotFound:
        pass
    except Exception as e:
        f["errors"].append(f"branches: {e}")

    # tree
    branch = repo.get("default_branch") or "main"
    try:
        tree, _ = api(f"/repos/{full}/git/trees/{urllib.parse.quote(branch)}?recursive=1")
    except NotFound:
        f["errors"].append("empty repo / no default branch")
        return f
    except Exception as e:
        f["errors"].append(f"tree: {e}")
        return f
    if tree.get("truncated"):
        f["truncated"] = True

    blobs = [t for t in tree.get("tree", []) if t.get("type") == "blob"]
    for t in blobs:
        path = t["path"]
        base = path.rsplit("/", 1)[-1]
        low = path.lower()
        # IOC payload filenames -> fetch + hash
        if base in IOC_PAYLOAD_FILES or path.endswith("kitty/cat.py"):
            try:
                content = blob_bytes(full, t["sha"])
                h = sha256(content)
                hit = h in IOC_HASHES
                add("CRITICAL" if hit else "HIGH", "payload-file",
                    f"IOC payload filename '{base}' present"
                    + (f"; SHA-256 MATCHES known-malicious payload ({h})" if hit
                       else f"; SHA-256 {h} (name-based IOC, hash not in known set)"), path)
            except Exception as e:
                add("HIGH", "payload-file", f"IOC payload filename '{base}' present (fetch failed: {e})", path)
        # bundle.js -> hash-only (name is too generic to flag alone)
        elif base == "bundle.js":
            try:
                content = blob_bytes(full, t["sha"])
                h = sha256(content)
                if h in IOC_HASHES:
                    add("CRITICAL", "payload-file",
                        f"bundle.js SHA-256 MATCHES known-malicious Shai-Hulud payload ({h})", path)
            except Exception:
                pass
        # malicious workflow filename
        if IOC_WORKFLOW_NAMES.search(base) and "/workflows/" in low:
            add("CRITICAL", "workflow", f"IOC workflow filename: {base}", path)

    # workflow contents
    wf = [t for t in blobs if re.search(r"\.github/workflows/.+\.ya?ml$", t["path"], re.I)]
    f["workflows"] = len(wf)
    for t in wf:
        try:
            text = blob_bytes(full, t["sha"]).decode("utf-8", "replace")
        except Exception as e:
            f["errors"].append(f"workflow {t['path']}: {e}")
            continue
        for needle, desc in IOC_STRINGS.items():
            if needle in text:
                add("CRITICAL", "workflow", f"IOC string ({desc}) in workflow", t["path"])
        for rx, desc in WF_SUSPICIOUS:
            if rx.search(text):
                add("MEDIUM", "workflow", f"workflow {desc}", t["path"])

    # manifests + lockfiles
    for t in blobs:
        base = t["path"].rsplit("/", 1)[-1]
        if base == "package.json":
            f["manifests"] += 1
            try:
                text = blob_bytes(full, t["sha"]).decode("utf-8", "replace")
            except Exception as e:
                f["errors"].append(f"package.json {t['path']}: {e}")
                continue
            for needle, desc in IOC_STRINGS.items():
                if needle in text:
                    add("CRITICAL", "manifest", f"IOC string ({desc}) in package.json", t["path"])
            hooks, depnames, struct = scan_manifest(text)
            for h in hooks:
                add("HIGH", "manifest", f"suspicious lifecycle hook -> {h}", t["path"])
            for s in struct:
                add("CRITICAL", "manifest", s, t["path"])
            for d in depnames:
                add("MEDIUM", "manifest",
                    f"declares dependency whose NAME is on the compromised list: {d} "
                    f"(verify resolved version against lockfile)", t["path"])
        elif base in LOCK_NAMES:
            f["lockfiles"] += 1
            try:
                text = blob_bytes(full, t["sha"]).decode("utf-8", "replace")
            except Exception as e:
                f["errors"].append(f"lockfile {t['path']}: {e}")
                continue
            for needle, desc in IOC_STRINGS.items():
                if needle in text:
                    add("CRITICAL", "lockfile", f"IOC string ({desc}) in lockfile", t["path"])
            hits = scan_lockfile(base, text)
            for pkg, v in hits:
                if pkg == "__parse_error__":
                    f["errors"].append(f"lockfile parse {t['path']}: {v}")
                else:
                    add("CRITICAL", "lockfile",
                        f"COMPROMISED package pinned in lockfile: {pkg}@{v}", t["path"])
        elif base == "data.json" and "/" not in t["path"]:
            try:
                text = blob_bytes(full, t["sha"]).decode("utf-8", "replace")[:600]
                if "eyJ" in text and "==" in text:
                    add("HIGH", "exfil-artifact",
                        "root data.json resembles double-base64 encoded blob "
                        "(Shai-Hulud exfil artifact pattern)", t["path"])
            except Exception:
                pass
    return f


# ---------------------------------------------------------------- targets
def repos_for(target):
    """Enumerate the repositories belonging to a resolved target."""
    name = target["name"]
    if target["self"]:
        repos = paginate("/user/repos?per_page=100&affiliation=owner")
        return [r for r in repos
                if (r.get("owner") or {}).get("login", "").lower() == name.lower()]
    if target["kind"] == "org":
        return paginate(f"/orgs/{urllib.parse.quote(name)}/repos?per_page=100&type=all")
    return paginate(f"/users/{urllib.parse.quote(name)}/repos?per_page=100&type=owner")


# ---------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="scan.py",
        description="Read-only GitHub REST API scan for Shai-Hulud / Mini Shai-Hulud "
                    "indicators of compromise across the repositories of any org or user.",
        epilog=(
            "examples:\n"
            "  scan.py --self                 scan your own repositories (incl. private)\n"
            "  scan.py org:my-company         scan one organization\n"
            "  scan.py org:acme user:alice    scan several explicit targets\n"
            "  scan.py --all-orgs             scan every org you are a member of\n"
            "  scan.py --all-orgs --self      scan everything you can reach\n"
            "\n"
            "A TARGET is 'org:NAME', 'user:NAME', or a bare NAME (auto-detected).\n"
            "Auth uses $GITHUB_TOKEN, else the GitHub CLI ('gh auth login')."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("targets", nargs="*", metavar="TARGET",
                   help="org:NAME, user:NAME, or a bare NAME to scan")
    p.add_argument("--all-orgs", action="store_true",
                   help="add every organization the authenticated user belongs to")
    p.add_argument("--self", dest="scan_self", action="store_true",
                   help="add the authenticated user's own repositories (includes private)")
    p.add_argument("--out", metavar="FILE",
                   help="results JSON path (default: results.json beside this script)")
    p.add_argument("--workers", type=int, default=8, metavar="N",
                   help="number of parallel repository workers (default: 8)")
    return p


# ---------------------------------------------------------------- main
def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.targets and not args.all_orgs and not args.scan_self:
        parser.error("no targets given - pass org:/user: TARGETs, --self, or --all-orgs")

    global HDR
    HDR = ghcommon.headers(ghcommon.gh_token())

    print("== Shai-Hulud IOC scan ==", flush=True)
    print(f"compromised npm pkgs: {len(NPM_BAD)}  pypi: {len(PYPI_BAD)}", flush=True)

    targets = ghcommon.resolve_targets(args.targets, args.all_orgs, args.scan_self, HDR)

    all_repos = {}
    for t in targets:
        lbl = ghcommon.label(t)
        try:
            repos = repos_for(t)
        except NotFound:
            print(f"  [skip] {lbl}: not found or no access", flush=True)
            continue
        except Exception as e:
            print(f"  [skip] {lbl}: {e}", flush=True)
            continue
        all_repos[lbl] = repos
        print(f"{lbl}: {len(repos)} repos", flush=True)

    # de-duplicate repositories reachable through more than one target
    flat, seen = [], set()
    for repos in all_repos.values():
        for r in repos:
            fn = r.get("full_name")
            if fn and fn not in seen:
                seen.add(fn)
                flat.append(r)
    if not flat:
        print("== no repositories to scan ==", flush=True)
        return

    results = {"scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "targets": {}, "repo_results": [], "metadata_findings": [], "code_search": []}

    # metadata IOC scan
    for r in flat:
        nm = r["name"].lower()
        desc = (r.get("description") or "")
        if "shai-hulud" in nm or "shai_hulud" in nm:
            results["metadata_findings"].append(
                {"severity": "CRITICAL", "repo": r["full_name"], "detail": "repo name contains 'shai-hulud'"})
        if nm.endswith("-migration"):
            results["metadata_findings"].append(
                {"severity": "HIGH", "repo": r["full_name"], "detail": "repo name uses '-migration' exfil pattern"})
        if nm in ("siridar-ghola-567", "tleilaxu-ornithopter-43"):
            results["metadata_findings"].append(
                {"severity": "CRITICAL", "repo": r["full_name"], "detail": "repo name matches known Mini Shai-Hulud exfil repo"})
        for needle, d in IOC_STRINGS.items():
            if needle in desc:
                results["metadata_findings"].append(
                    {"severity": "CRITICAL", "repo": r["full_name"], "detail": f"IOC string in description ({d})"})

    # per-repo deep scan (threaded)
    done = 0
    workers = max(1, args.workers)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(scan_repo, r): r for r in flat}
        for fut in as_completed(futs):
            done += 1
            try:
                res = fut.result()
            except Exception as e:
                res = {"repo": futs[fut]["full_name"], "findings": [], "errors": [f"fatal: {e}"],
                       "truncated": False, "manifests": 0, "lockfiles": 0, "workflows": 0}
            results["repo_results"].append(res)
            if res["findings"]:
                print(f"  [!] {res['repo']}: {len(res['findings'])} finding(s)", flush=True)
            if done % 40 == 0:
                print(f"  ...{done}/{len(flat)} repos scanned", flush=True)

    results["targets"] = {lbl: len(rs) for lbl, rs in all_repos.items()}
    out_path = args.out or os.path.join(WORK, "results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=1)
    nf = sum(len(r["findings"]) for r in results["repo_results"]) + len(results["metadata_findings"])
    print(f"== deep scan done: {done} repos, {nf} repo/metadata findings ==", flush=True)
    print(f"== results written to {out_path} ==", flush=True)


if __name__ == "__main__":
    main()
