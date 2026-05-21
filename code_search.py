#!/usr/bin/env python3
"""Supplementary GitHub code-search sweep for Shai-Hulud content IOCs.

Code search only indexes default branches and has size/index limits, so this
complements (does not replace) the authoritative git-tree scan in scan.py.
Search scopes are supplied on the command line (org:NAME / user:NAME), via
--self, or via --all-orgs; nothing is hard-coded.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

import ghcommon

WORK = os.path.dirname(os.path.abspath(__file__))
HDR = None  # request headers, populated in main()

# (query term, human label). Terms chosen to be specific & code-search-tokenisable.
QUERIES = [
    ("router_init.js", "Mini Shai-Hulud payload filename"),
    ("tanstack_runner.js", "Mini Shai-Hulud payload filename"),
    ("setup_bun.js", "Shai-Hulud fake-Bun payload filename"),
    ("bun_environment.js", "Shai-Hulud Second-Coming payload filename"),
    ("environment_source.js", "Shai-Hulud payload filename"),
    ("shai-hulud-workflow", "Shai-Hulud malicious workflow"),
    ("actionsSecrets.json", "Shai-Hulud secrets-exfil artifact"),
    ("IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner", "Mini Shai-Hulud wipe-threat string"),
    ("firedalazer", "Mini Shai-Hulud C2 dead-drop keyword"),
    ("voicproducoes", "Mini Shai-Hulud threat actor (May-11)"),
    ("0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa", "Mini Shai-Hulud PBKDF2 master key"),
    ("api.masscan.cloud", "Mini Shai-Hulud C2 domain"),
    ("git-tanstack.com", "Mini Shai-Hulud C2 domain"),
    ("npmjs.help", "Shai-Hulud phishing domain"),
    ('"@tanstack/setup"', "Mini Shai-Hulud fake package reference"),
]


def search(q, retries=5):
    """Run one code-search query; returns (json_result_or_None, error_or_None)."""
    url = "https://api.github.com/search/code?per_page=50&q=" + urllib.parse.quote(q)
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=HDR)
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8", "replace")), None
        except urllib.error.HTTPError as e:
            if e.code in (403, 429):
                rem = e.headers.get("X-RateLimit-Remaining")
                if rem == "0":
                    reset = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
                    time.sleep(max(5, reset - int(time.time()) + 3))
                else:
                    time.sleep(15 * (attempt + 1))
                continue
            if e.code == 422:
                return {"items": []}, "422 unprocessable (query rejected)"
            if e.code >= 500:
                time.sleep(5)
                continue
            return None, f"HTTP {e.code}"
        except Exception:
            time.sleep(5)
    return None, "exhausted retries"


def build_parser():
    p = argparse.ArgumentParser(
        prog="code_search.py",
        description="GitHub code-search sweep for Shai-Hulud content IOCs across "
                    "the repositories of any org or user. Complements scan.py.",
        epilog=(
            "examples:\n"
            "  code_search.py --self              search your own account\n"
            "  code_search.py org:my-company      search one organization\n"
            "  code_search.py org:acme user:alice search several scopes\n"
            "  code_search.py --all-orgs          search every org you belong to\n"
            "\n"
            "A SCOPE is 'org:NAME', 'user:NAME', or a bare NAME (auto-detected).\n"
            "Auth uses $GITHUB_TOKEN, else the GitHub CLI ('gh auth login')."),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("targets", nargs="*", metavar="SCOPE",
                   help="org:NAME, user:NAME, or a bare NAME to search")
    p.add_argument("--all-orgs", action="store_true",
                   help="add every organization the authenticated user belongs to")
    p.add_argument("--self", dest="scan_self", action="store_true",
                   help="add the authenticated user's own account")
    p.add_argument("--out", metavar="FILE",
                   help="results JSON path (default: code_search_results.json beside this script)")
    p.add_argument("--delay", type=float, default=7.0, metavar="SEC",
                   help="seconds to wait between queries, to respect the "
                        "code-search rate limit of ~10/min (default: 7)")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not args.targets and not args.all_orgs and not args.scan_self:
        parser.error("no scopes given - pass org:/user: SCOPEs, --self, or --all-orgs")

    global HDR
    HDR = ghcommon.headers(ghcommon.gh_token())

    targets = ghcommon.resolve_targets(args.targets, args.all_orgs, args.scan_self, HDR)
    scopes = [ghcommon.label(t) for t in targets]
    print(f"== Shai-Hulud code-search sweep: {len(QUERIES)} terms x {len(scopes)} scope(s) ==",
          flush=True)

    out = {"scopes": scopes, "queries": [], "errors": []}
    for term, lbl in QUERIES:
        for scope in scopes:
            q = f"{term} {scope}"
            res, err = search(q)
            rec = {"term": term, "label": lbl, "scope": scope,
                   "total": None, "matches": [], "error": err}
            if res is not None:
                rec["total"] = res.get("total_count", 0)
                for it in res.get("items", []):
                    rec["matches"].append({"repo": it.get("repository", {}).get("full_name"),
                                           "path": it.get("path"),
                                           "url": it.get("html_url")})
            flag = "!!" if (rec["total"] or 0) > 0 else "ok"
            print(f"[{flag}] {scope:22s} {term[:46]:46s} total={rec['total']} err={err}", flush=True)
            out["queries"].append(rec)
            time.sleep(max(0.0, args.delay))  # stay within the code-search rate limit

    out_path = args.out or os.path.join(WORK, "code_search_results.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    hits = sum(1 for q in out["queries"] if (q["total"] or 0) > 0)
    print(f"== code search done: {hits} query/scope pairs returned matches ==", flush=True)
    print(f"== results written to {out_path} ==", flush=True)


if __name__ == "__main__":
    main()
