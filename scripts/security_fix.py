"""Automatic fixes for the audit's GitHub findings, limited to changes that cannot break a working repository.

Two kinds, and nothing else:
- setting: a repository setting that only adds alerts, opens Dependabot pull requests, or blocks deleting or
  force-pushing the default branch. Applied directly.
- pr: a code change that behaves exactly as before (third-party actions pinned to the commit their tag points to
  today, plus a Dependabot config that keeps those pins current). Opened as a pull request on its own branch and never
  merged here. A pull request the user closed without merging is not opened again.

Keys, servers, org 2FA, workflow token permissions and every other finding stay with the user.
"""
import base64
import json
import re

import security_audit as sa

PIN_BRANCH = "security-audit/pin-actions"
RULESET_NAME = "security-audit: protect default branch"
COMMIT_TRAILER = "\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
PR_FOOTER = "\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)"
MAINLINE_BRANCHES = {"main", "master", "trunk", "develop", "dev", "production"}
FORCE_PUSH = re.compile(r"push\b[^\n]*(\s-f\b|--force)|force_push|force:\s*true")
USES_LINE = re.compile(r"^(\s*-?\s*uses:\s*)(['\"]?)([^@\s'\"]+)@([^\s'\"#]+)(['\"]?)(.*)$")
DEPENDABOT_CONFIG = """# Keeps the pinned GitHub Actions current: Dependabot opens a pull request when an action releases a new version.
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
"""


def gh_write(method, path, body=None):
    """Return (status, data). status is 200 on success, else the HTTP code (or 0 for other failures)."""
    cmd = ["gh", "api", "-X", method, path]
    if body is not None:
        cmd += ["--input", "-"]
    rc, out, err = sa.run(cmd, input=json.dumps(body) if body is not None else None)
    if rc != 0:
        m = re.search(r"HTTP (\d{3})", err)
        return (int(m.group(1)) if m else 0), err.strip()[-300:]
    try:
        return 200, json.loads(out) if out.strip() else None
    except ValueError:
        return 200, None


def action(f, kind, status, detail, url=""):
    return {"id": f["id"], "kind": kind, "status": status, "detail": detail, "url": url}


# ---------------------------------------------------------------------------- settings

def fix_dependabot(f, dry_run):
    repo = f["target"]
    if dry_run:
        return action(f, "setting", "would-fix", "Turn on Dependabot alerts and security update pull requests")
    st, err = gh_write("PUT", "repos/%s/vulnerability-alerts" % repo)
    if st != 200:
        return action(f, "setting", "failed", "Dependabot alerts: HTTP %s %s" % (st, err))
    st, _ = gh_write("PUT", "repos/%s/automated-security-fixes" % repo)
    detail = "Turned on Dependabot alerts" + (
        " and security update pull requests" if st == 200 else " (security updates failed: HTTP %s)" % st)
    return action(f, "setting", "fixed", detail, "https://github.com/%s/security/dependabot" % repo)


def fix_secret_scanning(f, dry_run):
    repo = f["target"]
    if dry_run:
        return action(f, "setting", "would-fix", "Turn on secret scanning and push protection")
    st, err = gh_write("PATCH", "repos/%s" % repo, {"security_and_analysis": {
        "secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}})
    if st != 200:
        return action(f, "setting", "failed", "Secret scanning: HTTP %s %s" % (st, err))
    return action(f, "setting", "fixed", "Turned on secret scanning and push protection",
                  "https://github.com/%s/settings/security_analysis" % repo)


def fix_branch(f, dry_run):
    repo, branch = f["target"].rsplit("@", 1)
    if branch not in MAINLINE_BRANCHES:
        return action(f, "setting", "skipped", "The default branch %s looks like a working branch, which may still be "
                      "rebased; set main as the default, or protect it by hand" % branch)
    st, files = sa.gh("repos/%s/contents/.github/workflows?ref=%s" % (repo, branch))
    for wf in files if st == 200 and isinstance(files, list) else []:
        st, text = sa.gh("repos/%s/contents/%s?ref=%s" % (repo, wf["path"], branch), raw=True)
        if st == 200 and FORCE_PUSH.search(text or ""):
            return action(f, "setting", "skipped", "%s force-pushes, so blocking force pushes could break it" %
                          wf["path"])
    what = "Block deleting and force-pushing %s (pushes and merges work as before)" % branch
    st, rulesets = sa.gh("repos/%s/rulesets" % repo)
    if st == 200 and any(r.get("name") == RULESET_NAME for r in rulesets or []):
        return action(f, "setting", "fixed", "Ruleset already in place")
    if dry_run:
        return action(f, "setting", "would-fix", what)
    st, data = gh_write("POST", "repos/%s/rulesets" % repo, {
        "name": RULESET_NAME, "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}]})
    if st != 200:
        return action(f, "setting", "failed", "Ruleset: HTTP %s %s" % (st, data))
    return action(f, "setting", "fixed", "Added a ruleset that blocks deleting and force-pushing %s" % branch,
                  "https://github.com/%s/rules/%s" % (repo, (data or {}).get("id", "")))


# ---------------------------------------------------------------------------- pull request: pin actions

def pin_text(text, resolve):
    """Pin every third-party `uses: owner/repo@tag` in a workflow to a commit SHA, keeping the tag as a comment.

    `resolve(owner_repo, ref)` returns the 40-character SHA, or None to leave the line alone.
    Returns (new_text, ["owner/repo@tag -> sha", ...]).
    """
    out, pinned = [], []
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        eol = line[len(body):]
        m = USES_LINE.match(body)
        if m:
            lead, q1, name, ref, q2, rest = m.groups()
            owner = name.split("/")[0].lower()
            third_party = not (name.startswith("./") or name.startswith("docker://") or
                               owner in sa.FIRST_PARTY_ACTION_OWNERS or re.fullmatch(r"[0-9a-f]{40}", ref))
            commit = resolve("/".join(name.split("/")[:2]), ref) if third_party else None
            if commit:
                comment = rest if "#" in rest else rest.rstrip() + " # " + ref
                body = "%s%s%s@%s%s%s" % (lead, q1, name, commit, q2, comment)
                pinned.append("%s@%s -> %s" % (name, ref, commit[:12]))
        out.append(body + eol)
    return "".join(out), pinned


def resolver():
    cache = {}

    def resolve(action_repo, ref):
        key = "%s@%s" % (action_repo, ref)
        if key not in cache:
            st, c = sa.gh("repos/%s/commits/%s" % (action_repo, ref))
            sha_ = (c or {}).get("sha") if st == 200 else None
            cache[key] = sha_ if sha_ and re.fullmatch(r"[0-9a-f]{40}", sha_) else None
        return cache[key]
    return resolve


def fix_pins(repo, fs, dry_run, resolve):
    st, info = sa.gh("repos/%s" % repo)
    if st != 200:
        return [action(f, "pr", "failed", "Could not read %s: HTTP %s" % (repo, st)) for f in fs]
    base = info.get("default_branch") or "main"
    st, prs = sa.gh("repos/%s/pulls?state=all&head=%s:%s&per_page=5" % (repo, repo.split("/")[0], PIN_BRANCH))
    if st == 200 and prs:
        last = prs[0]
        if last.get("state") == "open":
            return [action(f, "pr", "pr-open", "Pull request already open", last.get("html_url", "")) for f in fs]
        if not last.get("merged_at"):
            return [action(f, "pr", "declined", "You closed the earlier pull request without merging, so it is not "
                           "opened again. Accept the finding to hide it.", last.get("html_url", "")) for f in fs]
    changes, pinned = {}, []
    for f in fs:
        path = "/".join(f["target"].split("/")[2:])
        st, meta = sa.gh("repos/%s/contents/%s?ref=%s" % (repo, path, base))
        if st != 200 or not meta or "content" not in meta:
            continue
        text = base64.b64decode(meta["content"]).decode("utf-8")
        new, done = pin_text(text, resolve)
        if new != text:
            changes[path] = (new, meta["sha"])
            pinned += ["%s: %s" % (path, p) for p in done]
    if not changes:
        return [action(f, "pr", "failed", "No action tag could be resolved to a commit") for f in fs]
    st_d, _ = sa.gh("repos/%s/contents/.github/dependabot.yml?ref=%s" % (repo, base))
    st_d2, _ = sa.gh("repos/%s/contents/.github/dependabot.yaml?ref=%s" % (repo, base))
    add_dependabot = st_d == 404 and st_d2 == 404
    title = "Pin third-party GitHub Actions to commit SHAs"
    if dry_run:
        extra = " and add a Dependabot config for actions" if add_dependabot else ""
        return [action(f, "pr", "would-open-pr", "Pin %d action reference(s)%s" % (len(pinned), extra)) for f in fs]
    st, ref = sa.gh("repos/%s/git/ref/heads/%s" % (repo, base))
    if st != 200:
        return [action(f, "pr", "failed", "Could not read %s: HTTP %s" % (base, st)) for f in fs]
    gh_write("DELETE", "repos/%s/git/refs/heads/%s" % (repo, PIN_BRANCH))  # our own leftover from a merged PR
    st, err = gh_write("POST", "repos/%s/git/refs" % repo,
                       {"ref": "refs/heads/" + PIN_BRANCH, "sha": ref["object"]["sha"]})
    if st != 200:
        return [action(f, "pr", "failed", "Could not create the branch: HTTP %s %s" % (st, err)) for f in fs]
    writes = [(p, new, file_sha, "Pin third-party actions in %s to commit SHAs" % p.rsplit("/", 1)[-1])
              for p, (new, file_sha) in sorted(changes.items())]
    if add_dependabot:
        writes.append((".github/dependabot.yml", DEPENDABOT_CONFIG, None,
                       "Add Dependabot config to keep pinned actions current"))
    for path, text, file_sha, msg in writes:
        body = {"message": msg + COMMIT_TRAILER, "branch": PIN_BRANCH,
                "content": base64.b64encode(text.encode("utf-8")).decode()}
        if file_sha:
            body["sha"] = file_sha
        st, err = gh_write("PUT", "repos/%s/contents/%s" % (repo, path), body)
        if st != 200:
            gh_write("DELETE", "repos/%s/git/refs/heads/%s" % (repo, PIN_BRANCH))
            return [action(f, "pr", "failed", "Could not write %s: HTTP %s %s" % (path, st, err)) for f in fs]
    lines = "\n".join("- `%s`" % p for p in pinned)
    dep = ("\n\nIt also adds `.github/dependabot.yml` for the `github-actions` ecosystem, so Dependabot opens a pull "
           "request when one of these actions releases a new version.") if add_dependabot else ""
    pr_body = ("Pins each third-party GitHub Action to the commit its tag points to today. The workflows run exactly "
               "the same code as now, but a retagged or hijacked release can no longer change what runs here (the "
               "2025 tj-actions/changed-files compromise worked that way). Each line keeps the tag as a comment.\n\n"
               "%s%s\n\nOpened by the weekly security audit. It never merges its own pull requests.%s") % (
                   lines, dep, PR_FOOTER)
    st, pr = gh_write("POST", "repos/%s/pulls" % repo,
                      {"title": title, "head": PIN_BRANCH, "base": base, "body": pr_body})
    if st != 200:
        return [action(f, "pr", "failed", "Could not open the pull request: HTTP %s %s" % (st, pr)) for f in fs]
    return [action(f, "pr", "pr-opened", title, pr.get("html_url", "")) for f in fs]


# ---------------------------------------------------------------------------- entry point

SETTING_FIXES = {"dependabot-off": fix_dependabot, "secret-scanning-off": fix_secret_scanning,
                 "unprotected-branch": fix_branch}


def apply_fixes(findings, dry_run=False):
    """Fix what can be fixed safely among open `findings`; return one action per finding touched."""
    actions, pins = [], {}
    resolve = resolver()
    for f in findings:
        if f["area"] != "github":
            continue
        fn = SETTING_FIXES.get(f["check"])
        if fn and f["target"] != "private-repos":
            try:
                actions.append(fn(f, dry_run))
            except Exception as e:  # noqa: BLE001 - one failed fix must not stop the others
                actions.append(action(f, "setting", "failed", str(e)))
        elif f["check"] == "unpinned-action":
            pins.setdefault("/".join(f["target"].split("/")[:2]), []).append(f)
    for repo, fs in sorted(pins.items()):
        try:
            actions += fix_pins(repo, fs, dry_run, resolve)
        except Exception as e:  # noqa: BLE001
            actions += [action(f, "pr", "failed", str(e)) for f in fs]
    return actions
