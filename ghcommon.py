#!/usr/bin/env python3
"""Shared GitHub helpers for the Shai-Hulud IOC scanners.

Centralises token acquisition, authenticated REST calls with rate-limit
handling, and target resolution so that scan.py and code_search.py stay
repository-agnostic: callers pass `org:NAME` / `user:NAME` targets (or the
--all-orgs / --self flags) instead of hard-coding any account.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

API = "https://api.github.com"
USER_AGENT = "shai-hulud-ioc-scanner"


class NotFound(Exception):
    """Raised for 404/409/451 — resource absent, empty, or access-blocked."""


# ---------------------------------------------------------------- auth
def gh_token():
    """Return a GitHub token.

    Prefers the GITHUB_TOKEN / GH_TOKEN environment variables; otherwise
    falls back to the GitHub CLI (`gh auth token`). Exits with a helpful
    message if neither is available.
    """
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok and tok.strip():
        return tok.strip()
    try:
        r = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("error: no GITHUB_TOKEN set and the GitHub CLI ('gh') is not installed.\n"
                 "       Set GITHUB_TOKEN, or install gh and run 'gh auth login'.")
    tok = (r.stdout or "").strip()
    if not tok:
        sys.exit("error: could not obtain a GitHub token.\n"
                 "       Set GITHUB_TOKEN, or run 'gh auth login'.")
    return tok


def headers(token):
    """Build the standard authenticated request headers."""
    return {"Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
            "X-GitHub-Api-Version": "2022-11-28"}


# ---------------------------------------------------------------- HTTP
def request(path, hdr, raw=False, retries=4):
    """GET `path` (absolute URL or /-relative) with retry + rate-limit handling.

    Returns (parsed_json_or_bytes, response_headers). Raises NotFound for
    404/409/451 and RuntimeError if all retries are exhausted.
    """
    url = path if path.startswith("http") else API + path
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=hdr)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data = r.read()
                rhdrs = dict(r.headers)
                if raw:
                    return data, rhdrs
                return json.loads(data.decode("utf-8", "replace")), rhdrs
        except urllib.error.HTTPError as e:
            if e.code in (404, 409, 451):
                raise NotFound(f"{e.code} {path}")
            if e.code in (403, 429):
                rem = e.headers.get("X-RateLimit-Remaining")
                if rem == "0":
                    reset = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
                    wait = min(max(5, reset - int(time.time()) + 3), 900)
                    sys.stderr.write(f"[rate-limit] sleeping {wait}s\n")
                    time.sleep(wait)
                else:
                    time.sleep(20 * (attempt + 1))  # secondary rate limit
                continue
            if e.code >= 500:
                time.sleep(3 * (attempt + 1))
                continue
            raise
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            time.sleep(3 * (attempt + 1))
    raise RuntimeError(f"giving up on {path}")


def paginate(path, hdr):
    """Follow GitHub's Link-header pagination and return every item."""
    out = []
    while path:
        items, rhdrs = request(path, hdr)
        out.extend(items)
        path = None
        for part in rhdrs.get("Link", "").split(","):
            if 'rel="next"' in part:
                path = part[part.find("<") + 1:part.find(">")]
    return out


# ---------------------------------------------------------------- identity
def whoami(hdr):
    """Login of the authenticated user."""
    data, _ = request("/user", hdr)
    return data.get("login")


def member_orgs(hdr):
    """Logins of every organization the authenticated user belongs to."""
    return [o["login"] for o in paginate("/user/orgs?per_page=100", hdr)]


# ---------------------------------------------------------------- targets
def label(target):
    """Human-readable 'kind:name' label for a resolved target."""
    return f"{target['kind']}:{target['name']}"


def _classify(name, hdr):
    """Classify a bare (unprefixed) name as an org or a user via the API."""
    try:
        request(f"/orgs/{name}", hdr)
        return "org"
    except NotFound:
        return "user"


def resolve_targets(specs, all_orgs, include_self, hdr):
    """Turn CLI specs and flags into an ordered, de-duplicated target list.

    Arguments:
      specs        -- list of strings: "org:NAME", "user:NAME", or bare "NAME".
      all_orgs     -- if True, add every org the authenticated user belongs to.
      include_self -- if True, add the authenticated user's own account.
      hdr          -- request headers from headers().

    Returns a list of dicts: {"kind": "org"|"user", "name": str, "self": bool}.
    The "self" flag marks the authenticated account, for which private
    repositories are reachable via /user/repos.
    """
    targets = []
    seen = set()

    def add(kind, name, is_self=False):
        key = (kind, name.lower())
        if key not in seen:
            seen.add(key)
            targets.append({"kind": kind, "name": name, "self": is_self})

    if include_self:
        me = whoami(hdr)
        if me:
            add("user", me, is_self=True)
    if all_orgs:
        orgs = member_orgs(hdr)
        sys.stderr.write(f"[resolve] --all-orgs: {len(orgs)} organization(s): "
                         f"{', '.join(orgs) or 'none'}\n")
        for org in orgs:
            add("org", org)
    for spec in specs:
        spec = spec.strip()
        if not spec:
            continue
        if ":" in spec:
            kind, _, name = spec.partition(":")
            kind, name = kind.strip().lower(), name.strip()
            if kind not in ("org", "user"):
                sys.exit(f"error: unknown target prefix in '{spec}' - use 'org:' or 'user:'")
            if not name:
                sys.exit(f"error: empty target name in '{spec}'")
        else:
            name = spec
            kind = _classify(name, hdr)
            sys.stderr.write(f"[resolve] '{name}' -> {kind}\n")
        add(kind, name)

    if not targets:
        sys.exit("error: no targets resolved - pass org:/user: targets, --self, or --all-orgs.")
    return targets
