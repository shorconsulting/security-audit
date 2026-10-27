"""Fix groups: the audit's findings bundled into the changes that fix them, with what each change touches and the
connectivity checks run before and after it.

A group is one change in one place, verified by one set of checks: the same kind of fix on the same key, server,
repository, organization or Mac setting. Two committed secrets in one repository are one group (one review, one pull
request); the same kind of secret in another repository is another group.

Each group carries:
- touches: what the change can affect, from this run's data (who logged in to the server this week and how, which
  ssh logins and scheduled jobs use the key, which services listen);
- steps and rollback: the runbook `/security-audit fix-group <id>` follows;
- checks: connectivity tests snapshotted before the change and compared after it. Anything that worked before and fails
  after is a regression: the fix is rolled back.
"""
import glob
import json
import os
import re
import socket

import security_audit as sa

FIXES_FILE = os.path.join(sa.STATE_DIR, "fixes.json")
SNAP_DIR = os.path.join(sa.STATE_DIR, "connectivity")
IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
SSH_GROUP_CHECKS = {"root-password-login", "password-login", "root-login", "empty-passwords", "x11", "pw-accounts",
                    "no-fail2ban"}
PATCH_CHECKS = {"security-updates", "updates", "reboot", "no-auto-updates"}
FIREWALL_CHECKS = {"no-firewall", "exposed-port", "container-port"}
INCIDENT_CHECKS = {"miner", "worm-ioc", "extra-uid0", "worm-repo", "worm-runner", "worm-workflow", "malicious-package"}
WORKFLOW_CHECKS = {"unpinned-action", "prt-checkout", "script-injection", "no-permissions"}
REPO_SETTING_CHECKS = {"unprotected-branch", "deploy-key-write", "secret-scanning-off", "dependabot-off"}
GITHUB_REVIEW_CHECKS = {"member-new", "outside-new", "hooks-new", "runners-new", "deploy-keys-new", "user-key-new",
                        "repo-went-public"}
CLAUDE_PERMISSION_CHECKS = {"broad-allow", "bypass-mode", "all-project-mcp"}
CLAUDE_PLUGIN_CHECKS = {"exfil-pattern", "hidden-unicode", "injection-phrase", "third-party-plugin", "local-plugin",
                        "plugin-new", "plugin-changed"}
MAC_REVIEW_CHECKS = {"launch-new", "launch-script", "launch-unsigned", "new-listener", "rc-changed", "rc-suspicious",
                     "mac-authkey-new"}


def slug(text):
    return re.sub(r"[^a-z0-9._]+", "-", text.lower()).strip("-")[:60]


def repo_of(target):
    return "/".join(re.split(r"[|@#]", target)[0].split("/")[:2])


def checkout_of(f):
    """Local checkout path (with ~) of a secrets or supply finding."""
    d = f.get("detail") or ""
    if f["check"] == "committed-secret":
        return d.split(" at ")[0]
    if f["check"] == "env-tracked":
        return d.split(" in ")[-1]
    return re.split(r"[|:]", f["target"])[0]


def remote_of(checkout):
    rc, out, _ = sa.run(["git", "-C", os.path.expanduser(checkout), "remote", "get-url", "origin"], 10)
    m = re.search(r"github\.com[:/]([^/\s]+/[^/\s]+?)(\.git)?$", out.strip()) if rc == 0 else None
    return m.group(1) if m else None


def classify(f, remotes):
    """(kind, scope) of the group a finding belongs to."""
    area, check, target = f["area"], f["check"], f["target"]
    ip = (IP.search(target) or [None])[0] if area == "servers" else None
    if area == "keys":
        return ("mac-review", "keys") if check == "mac-authkey-new" else ("key", target)
    if area == "servers":
        if check in SSH_GROUP_CHECKS:
            return "server-ssh", ip or target
        if check in PATCH_CHECKS:
            return "server-patch", ip or target
        if check in FIREWALL_CHECKS:
            return "server-firewall", ip or target
        if check in INCIDENT_CHECKS:
            return "server-incident", ip or target
        return "server-review", ip or target
    if check in INCIDENT_CHECKS:
        return "incident", target
    if area == "secrets":
        if check in ("committed-secret", "env-tracked"):  # one group per GitHub repo, however many clones have it
            co = checkout_of(f)
            return "secrets", remotes.get(co) or co
        return "local-secrets", "mac"
    if area == "supply":
        co = checkout_of(f)
        return ("deps", remotes.get(co) or co)
    if area == "github":
        repo = repo_of(target)
        if check == "org-2fa":
            return "org-2fa", target
        if check.startswith("org-"):
            return "org-settings", target
        if check == "secret-scanning-off" and target == "private-repos":
            return "github-plan", "secret-protection"
        if check in WORKFLOW_CHECKS or check.startswith("zizmor-"):
            return "workflows", repo
        if check in REPO_SETTING_CHECKS:
            return "repo-settings", repo
        if check == "dependabot-open":
            return "deps", repo
        if check == "secret-alert":
            return "secrets-github", repo
        return "github-review", f["id"]
    if area == "mac":
        if check in MAC_REVIEW_CHECKS:
            return "mac-review", target
        if check == "sharing":
            return "mac-sharing", "mac"
        return "mac-settings", "mac"
    if area == "claude":
        if check in CLAUDE_PERMISSION_CHECKS:
            return "claude-permissions", "settings"
        if check in CLAUDE_PLUGIN_CHECKS:
            return "claude-plugin", target.split("|")[0]
        return "claude-review", f["id"]
    return "other", f["id"]


# ---------------------------------------------------------------------------- local facts

def hosts_by_ip():
    out = {}
    for h in sa.ssh_hosts():
        try:
            ip = socket.gethostbyname(h["hostname"])
        except OSError:
            ip = h["hostname"]
        out.setdefault(ip, []).append(h)
    return out


def automation_refs(needles, alias_needles=()):
    """Scheduled tasks, launch items and cron lines that mention a key file or ssh to one of the aliases."""
    refs = []
    pats = [re.compile(re.escape(n)) for n in needles if n]
    pats += [re.compile(r"\bssh\b[^\n]{0,80}\b%s\b" % re.escape(a)) for a in alias_needles if a]
    places = [(p, "scheduled task " + p.split("/")[-2]) for p in
              glob.glob(os.path.join(sa.HOME, ".claude", "scheduled-tasks", "*", "SKILL.md"))]
    for d in (os.path.join(sa.HOME, "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"):
        places += [(p, "launch item " + os.path.basename(p)) for p in glob.glob(os.path.join(d, "*.plist"))]
    for path, label in places:
        text = sa.read_text(path, 200_000) or ""
        if any(p.search(text) for p in pats):
            refs.append(label)
    rc, out, _ = sa.run(["crontab", "-l"], 10)
    for line in out.splitlines() if rc == 0 else []:
        if not line.startswith("#") and any(p.search(line) for p in pats):
            refs.append("cron: " + line.strip()[:100])
    return sorted(set(refs))


# ---------------------------------------------------------------------------- group builders

def ssh_check(alias):
    return {"type": "ssh", "alias": alias, "label": "ssh %s" % alias}


def server_checks(ip, srv, hosts):
    checks = [ssh_check(h["alias"]) for h in hosts]
    root = next((h["alias"] for h in hosts if h["user"] == "root"), srv.get("alias") if srv.get("root") else None)
    if root:
        checks.append({"type": "units", "alias": root, "label": "failed services on %s" % root})
    ports = sorted({p.split("|")[0] for p in srv.get("tcp", [])} - {"22"}, key=lambda p: int(p) if p.isdigit() else 0)
    for p in ports[:8]:
        checks.append({"type": "tcp", "host": ip, "port": p, "label": "port %s on %s" % (p, ip)})
    for p, scheme in (("443", "https"), ("80", "http")):
        if p in ports:
            checks.append({"type": "http", "url": "%s://%s/" % (scheme, ip), "label": "%s://%s answers" % (scheme, ip)})
    return checks


def describe_logins(srv):
    if not srv:
        return []
    out = []
    logins = srv.get("logins") or []
    if logins:
        out.append("Logins in the last 7 days: %s." % ", ".join(
            "%s (%s)" % tuple((l.split("|") + ["?"])[:2]) for l in logins[:8]) + (" and more" if len(logins) > 8 else ""))
    m = srv.get("login_methods") or {}
    if m:
        out.append("By method: %s." % ", ".join("%s %d" % (k, v) for k, v in sorted(m.items())))
    return out


def build_key(g, fs, ctx):
    key = fs[0]["target"]
    path = os.path.expanduser(key)
    name = os.path.basename(key)
    uses = [h for hs in ctx["hosts"].values() for h in hs if path in h["identityfiles"]]
    opens = next((f["detail"][len("Opens: "):].rstrip(".") for f in fs if f["detail"].startswith("Opens: ")), "")
    auto = automation_refs([name], [h["alias"] for h in uses])
    g["title"] = "Protect SSH key %s" % name
    g["who"] = "You type the passphrase; Claude does the rest and checks every login with you"
    t = []
    if opens:
        t.append("Logins that use this key: %s." % opens)
    else:
        t.append("No ssh config entry uses this key, so something else may (a bot, a script, another tool). Find "
                 "it before changing the key, or restrict the key on the servers and accept the finding.")
    t.append("After a passphrase is added, the first use after each login or restart asks for it, unless it is "
             "stored in the macOS keychain (then it unlocks with your Mac login).")
    if auto:
        t.append("Unattended jobs that use it: %s. They keep working only while the key is loaded in the agent; "
                 "after a restart they fail until the key is unlocked once." % ", ".join(auto))
    else:
        t.append("No scheduled task, launch item or cron job on this Mac mentions this key or its servers.")
    g["touches"] = t
    g["steps"] = [
        "Run the checks below and save the result as `before`.",
        "You run `ssh-keygen -p -f %s` in Terminal and choose a passphrase (Claude never types or sees it)." % key,
        "Store it in the keychain: `ssh-add --apple-use-keychain %s`." % key,
        "Make sure `~/.ssh/config` has `UseKeychain yes` and `AddKeysToAgent yes` under `Host *`.",
        "Run the checks again and compare with `before`.",
    ]
    g["rollback"] = ["Remove the passphrase again with `ssh-keygen -p -f %s` (enter the old one, leave the new one "
                     "empty)." % key]
    g["checks"] = [ssh_check(h["alias"]) for h in uses]
    if "github.com" in opens:
        g["checks"].append({"type": "github-ssh", "key": path, "label": "GitHub accepts %s" % name})


def build_server(g, fs, ctx):
    ip = g["scope"]
    srv = ctx["servers"].get(ip, {})
    hosts = ctx["hosts"].get(ip, [])
    label = srv.get("label") or (hosts[0]["alias"] if hosts else ip)
    root_alias = next((h["alias"] for h in hosts if h["user"] == "root"), label)
    checks = {f["check"] for f in fs}
    g["checks"] = server_checks(ip, srv, hosts)
    if g["kind"] == "server-ssh":
        g["title"] = "Harden SSH on %s" % label
        g["who"] = "Claude, with your OK; a logged-in control connection stays open throughout"
        t = describe_logins(srv)
        pw = (srv.get("login_methods") or {}).get("password", 0) + \
            (srv.get("login_methods") or {}).get("keyboard-interactive/pam", 0)
        if srv.get("login_methods"):
            t.append("%d login(s) this week used a password: whoever made them loses access when passwords are "
                     "turned off. Find them first." % pw if pw else
                     "Every login this week used a key, so turning off passwords locks no one out. Key logins "
                     "(this Mac, keysync computers, CI deploys) are unaffected.")
        elif srv:
            t.append("The login log could not be read (no root), so it is unknown whether anyone logs in with a "
                     "password. Check before turning passwords off.")
        else:
            t.append("This report has no login data for the server yet (the next audit records it). Check who logs "
                     "in with a password before turning passwords off.")
        if srv.get("failed_logins"):
            t.append("The %s failed password attempts this week stop at once." % format(srv["failed_logins"], ","))
        if "pw-accounts" in checks:
            t.append("Accounts keep their passwords for sudo and the provider's web console; only SSH stops "
                     "accepting them.")
        g["touches"] = t
        lines = ["PasswordAuthentication no", "KbdInteractiveAuthentication no"]
        if checks & {"root-password-login", "root-login"}:
            lines.append("PermitRootLogin prohibit-password")
        if "empty-passwords" in checks:
            lines.append("PermitEmptyPasswords no")
        if "x11" in checks:
            lines.append("X11Forwarding no")
        if checks <= {"x11", "no-fail2ban"}:
            lines = ["X11Forwarding no"] if "x11" in checks else []
        g["steps"] = ["Run the checks below and save the result as `before`.",
                      "Open a control connection that stays logged in: `ssh -fNM -S ~/.security-audit/ctl-%s -o ControlPersist=45m %s`, and send every server command through it (`ssh -S ~/.security-audit/ctl-%s %s ...`), so a rollback still works even if new logins fail." % (root_alias, root_alias, root_alias, root_alias)]
        if lines:
            g["steps"] += [
                "Write `/etc/ssh/sshd_config.d/00-security-audit.conf` with: %s. (The `00-` name sorts first, so it "
                "wins over a cloud-init file that turns passwords back on.)" % "; ".join("`%s`" % l for l in lines),
                "Test the config with `sshd -t`, then `systemctl reload ssh`.",
                "From the Mac, confirm a password login is now refused: `ssh -o PubkeyAuthentication=no -o "
                "PreferredAuthentications=password root@%s` must answer `Permission denied (publickey)`." % ip]
        if "no-fail2ban" in checks:
            g["steps"].append("Install brute-force protection: `apt install -y fail2ban` (its default sshd jail).")
        g["steps"].append("Run the checks again in a new session and compare with `before`.")
        g["rollback"] = ["Through the control connection: `rm /etc/ssh/sshd_config.d/00-security-audit.conf && "
                         "systemctl reload ssh`."] + (["`apt remove -y fail2ban` if it blocks a legitimate address."]
                                            if "no-fail2ban" in checks else [])
    elif g["kind"] == "server-patch":
        g["title"] = "Patch and reboot %s" % label
        g["who"] = "Claude, with your OK on the time"
        procs = sorted({"%s (%s)" % (p.split("|")[1] or "?", p.split("|")[0]) for p in srv.get("tcp", [])})
        t = ["Services that restart: %s." % ", ".join(procs[:10]) if procs else
             "Every service on the server restarts."]
        if "reboot" in checks:
            t.append("The reboot takes the server and its apps offline for about 1 to 3 minutes; pick a quiet time.")
        t.append("Package upgrades can change app behaviour; the checks below confirm the same services answer "
                 "afterwards.")
        g["touches"] = t
        g["steps"] = ["Run the checks below and save the result as `before`.",
                      "`apt update && apt upgrade -y` on %s." % root_alias]
        if "no-auto-updates" in checks:
            g["steps"].append("Turn on automatic security updates: `apt install -y unattended-upgrades && "
                              "dpkg-reconfigure -f noninteractive unattended-upgrades`.")
        if "reboot" in checks or "security-updates" in checks:
            g["steps"].append("`reboot`, wait for SSH to come back.")
        g["steps"].append("Run the checks again and compare with `before`; check `systemctl --failed`.")
        g["rollback"] = ["A service that fails after the upgrade: restart it and read `journalctl -u <service>`; "
                         "a server that does not boot: boot the previous kernel from the provider's rescue console."]
    elif g["kind"] == "server-firewall":
        g["title"] = "Firewall on %s" % label
        g["who"] = "Claude, with your OK; a logged-in control connection stays open"
        procs = sorted({"%s (%s)" % (p.split("|")[0], p.split("|")[1] or "?") for p in srv.get("tcp", [])})
        t = ["Services listening on public addresses: %s." % ", ".join(procs) if procs else
             "No services listen on public addresses."]
        if srv.get("exposed"):
            t.append("Reachable from the internet today besides 22/80/443: %s. Anything that uses those ports from "
                     "outside (a database client, a CI job) stops working." % ", ".join(srv["exposed"]))
        t.append("Docker publishes ports around ufw; containers need `127.0.0.1:` bindings instead.")
        g["touches"] = t
        g["steps"] = ["Run the checks below and save the result as `before`.",
                      "Open a control connection that stays logged in: `ssh -fNM -S ~/.security-audit/ctl-%s -o ControlPersist=45m %s`, and send every server command through it (`ssh -S ~/.security-audit/ctl-%s %s ...`), so a rollback still works even if new logins fail." % (root_alias, root_alias, root_alias, root_alias),
                      "`ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw default deny incoming && "
                      "ufw enable` (add any port the checks show is used from outside).",
                      "Run the checks again and compare with `before`."]
        g["rollback"] = ["Through the control connection: `ufw disable`."]
    elif g["kind"] == "server-incident":
        g["title"] = "Possible compromise on %s" % label
        g["who"] = "You decide; Claude gathers evidence first and changes nothing until you say"
        g["touches"] = ["Everything the server holds: its secrets, deploy keys and data must be treated as known to an "
                        "attacker until shown otherwise."]
        g["steps"] = ["Capture evidence read-only (the process, its binary hash, its parent, network connections).",
                      "Decide with you: rebuild from a clean deploy (recommended) or clean in place.",
                      "Rotate every secret the server holds; remove its deploy keys from GitHub."]
        g["rollback"] = []
    else:
        g["title"] = "Confirm recent changes on %s" % label
        g["who"] = "You decide each item; Claude removes only what you say"
        g["touches"] = ["Nothing changes unless you remove something. Removing a key ends that computer's access; "
                        "removing a cron job, service or script stops what it does."]
        g["steps"] = ["Review each item below with Claude (it reads, never runs, the files involved).",
                      "Keep: `/security-audit accept <id> \"reason\"`. Remove: Claude removes it with your OK."]
        g["rollback"] = ["A removed key or cron line is restored from the copy Claude saves first in "
                         "`/root/security-audit-backup/`."]


def build_secrets(g, fs, ctx):
    scope = g["scope"]
    repo = scope if "/" in scope and not scope.startswith("~") else None
    clones = sorted({checkout_of(f) for f in fs})
    files, hits = {}, set()
    for f in fs:
        m = re.search(r" at (.+?):(\d+)", f["detail"])
        rule = f["target"].split(":")[0].rsplit("/", 1)[-1]
        if m:
            files.setdefault(m.group(1), 0)
            hits.add((rule, m.group(1), m.group(2)))
        else:
            hits.add((rule, f["target"], ""))
    tests = len({h for h in hits if sa.TEST_PATH.search(h[1])})
    g["title"] = "Committed secrets in %s" % (repo or os.path.basename(scope))
    g["who"] = "Claude reviews each with you; rotating a real secret at its provider is yours"
    t = ["%d secret(s) in %d file(s)%s: %s." % (len(hits), len(files), (", %d in test files" % tests) if tests else "",
                                                ", ".join(sorted(files)[:6]) + (" and more" if len(files) > 6 else ""))]
    if len(clones) > 1:
        t.append("Found in %d local clones of the repository (%s); it is one history, so one fix covers them all." % (
            len(clones), ", ".join(clones)))
    t.append("A made-up test value needs only a `.gitleaksignore` entry: one pull request, nothing else changes.")
    t.append("Rotating a real secret breaks every place that still has the old value until it is updated: env "
             "files on the servers, GitHub Actions secrets%s, hosting dashboards. The old value stays in git "
             "history either way, so anything real must be rotated, not just deleted." % (
                 " of %s" % repo if repo else ""))
    g["touches"] = t
    g["steps"] = ["Show each hit masked (prefix and length only) and decide with you: real, or made up.",
                  "Made up: add the fingerprints to `.gitleaksignore` in one pull request.",
                  "Real: you rotate it at the provider; Claude updates where it is used (`gh secret set -R %s`, "
                  "server env files), then moves it out of the code in the same pull request." % (repo or "<repo>"),
                  "Run the checks again and compare with `before`."]
    g["rollback"] = ["Put the previous value back where it was updated (Claude notes each place it changed)."]
    g["checks"] = [{"type": "ci", "repo": repo, "label": "CI on %s" % repo}] if repo else []


def build_repo(g, fs, ctx):
    repo = g["scope"]
    checks = {f["check"] for f in fs}
    ci = [{"type": "ci", "repo": repo, "label": "CI on %s" % repo}] if "/" in repo else []
    g["checks"] = ci
    if g["kind"] == "deps":
        g["title"] = "Vulnerable packages in %s" % repo
        g["who"] = "Claude, with your OK on each merge"
        g["touches"] = ["Package versions change; a major version can break the build or the app. Patch and minor "
                        "updates first, majors one at a time.",
                        "Dependabot opens the pull requests itself; each one runs CI before it can merge."]
        g["steps"] = ["Run the checks below and save the result as `before`.",
                      "List Dependabot pull requests: `gh pr list -R %s --author app/dependabot`." % repo,
                      "Merge the ones with green CI, patch and minor first; for a critical alert without a pull "
                      "request, update the package in one pull request.",
                      "Run the checks again and compare with `before`."]
        g["rollback"] = ["Revert the merge commit (`gh pr revert` or `git revert`)."]
    elif g["kind"] == "workflows":
        g["title"] = "Harden GitHub Actions in %s" % repo
        g["who"] = "Claude opens one pull request; you merge it"
        files = sorted({f["target"][len(repo) + 1:] for f in fs if f["target"].startswith(repo + "/")})
        g["touches"] = ["Workflows that change: %s." % ", ".join(files[:8]) if files else "The repository's workflows.",
                        "These run CI and deploys: a too-tight `permissions:` block or a changed trigger can make a "
                        "job fail or a deploy stop. Each change keeps what the job needs today."]
        if any(c.startswith("zizmor-dangerous") or c == "prt-checkout" for c in checks):
            g["touches"].append("pull_request_target and workflow_run jobs run with secrets; moving them to safer "
                                "triggers can change when auto-merge or review bots run.")
        g["steps"] = ["Run the checks below and save the result as `before`.",
                      "One pull request: values from issues and PRs go through `env:`, each job gets the narrowest "
                      "`permissions:`, risky triggers lose secrets or move to `pull_request`.",
                      "The pull request's CI must pass; after merge, the next run of each changed workflow must "
                      "pass (and the next deploy, for deploy workflows).",
                      "Run the checks again and compare with `before`."]
        g["rollback"] = ["Revert the pull request."]
    elif g["kind"] == "repo-settings":
        g["title"] = "Repository settings for %s" % repo
        g["who"] = "Claude, with your OK"
        t = []
        if "unprotected-branch" in checks:
            t.append("A branch rule blocks deleting and force-pushing the default branch; anything that force-pushes "
                     "it (a mirror job) must move to another branch first.")
        if "deploy-key-write" in checks:
            t.append("Making the deploy key read-only stops whatever pushes with it (a server, a mirror job); find "
                     "it first.")
        if "dependabot-off" in checks:
            t.append("Dependabot alerts only report; nothing changes in the code.")
        g["touches"] = t or ["Repository settings only."]
        g["steps"] = ["Run the checks below and save the result as `before`.",
                      "Apply each setting (the finding's fix line says which).",
                      "Run the checks again and compare with `before`."]
        g["rollback"] = ["Undo the setting in the repository's Settings page."]


def build_other(g, fs, ctx):
    kind, scope = g["kind"], g["scope"]
    titles = {
        "org-2fa": ("Require two-factor login in %s" % scope,
                    ["Members of %s without two-factor login are removed from the organization the moment it is "
                     "required, and lose access to its repositories. That includes bot or machine accounts whose "
                     "tokens CI uses." % scope,
                     "Listing who lacks it needs the `admin:org` scope (`gh auth refresh -s admin:org`)."],
                    ["List members without two-factor login: `gh api orgs/%s/members?filter=2fa_disabled`." % scope,
                     "Ask each to turn it on (or replace a bot account's token); wait until the list is empty.",
                     "Turn on the requirement: https://github.com/organizations/%s/settings/security" % scope,
                     "Confirm the member list is unchanged."],
                    ["Turn the requirement off on the same page and re-invite anyone removed."],
                    "You turn on the requirement; Claude checks who would be removed first"),
        "org-settings": ("Organization settings for %s" % scope,
                         ["Settings for new repositories and member permissions; existing repositories and members "
                          "are not affected."],
                         ["Apply each setting in https://github.com/organizations/%s/settings" % scope],
                         ["Change the setting back."], "You, in the organization's settings"),
        "claude-permissions": ("Tighten Claude Code permissions",
                               ["Claude asks before those commands again. Scheduled tasks that rely on them in Auto "
                                "mode can pause or be stopped; narrower rules keep what they need."],
                               ["Replace each broad rule with the narrow ones your tasks use (for example "
                                "`Bash(gh pr view *)` instead of `Bash(gh *)`), in the settings file named in each "
                                "finding.", "Run the next scheduled tasks and watch for new prompts."],
                               ["Restore the previous settings file (Claude saves a copy first)."],
                               "Claude edits the settings with your OK"),
        "claude-plugin": ("Review plugin %s" % scope,
                          ["Removing or editing the plugin removes its commands and anything scheduled that uses "
                           "them."],
                          ["Read the flagged files with Claude; keep (accept) or remove the plugin."],
                          ["Reinstall it from its marketplace."], "You decide; Claude reads the code with you"),
        "mac-settings": ("Mac settings",
                         ["System settings on this Mac only; nothing on servers or GitHub."],
                         ["Apply each setting in System Settings (the finding's fix line says where)."],
                         ["Change the setting back."], "You, in System Settings"),
        "mac-sharing": ("Sharing on this Mac",
                        ["Turning off Remote Login or File Sharing stops other computers and accounts that connect "
                         "to this Mac that way (for example ssh between accounts)."],
                        ["Turn off what is not used in System Settings > General > Sharing."],
                        ["Turn it back on."], "You, in System Settings"),
        "local-secrets": ("Credentials on this Mac",
                          ["Tightening file permissions changes nothing for you; replacing a token means logging in "
                           "again where it is used."],
                          ["Apply each finding's fix line."], ["Restore the previous file from the copy Claude saves."],
                          "Claude, with your OK"),
        "github-plan": ("Secret scanning on private repositories",
                        ["A paid GitHub plan (Secret Protection); the local gitleaks scan covers this meanwhile."],
                        ["Decide whether to buy it; nothing else to do."], [], "You"),
    }
    if kind in titles:
        g["title"], g["touches"], g["steps"], g["rollback"], g["who"] = titles[kind]
    else:
        g["title"] = fs[0]["title"] if len(fs) == 1 else "%s (%d items)" % (fs[0]["title"], len(fs))
        g["touches"] = ["Nothing changes unless you remove or change it."]
        g["steps"] = ["Confirm with Claude; keep it with `/security-audit accept <id> \"reason\"`, or follow the "
                      "finding's fix line."]
        g["rollback"] = []
        g["who"] = "You decide; Claude does it with your OK"
    g.setdefault("checks", [])


# ---------------------------------------------------------------------------- where, and production impact

IMPACT_LABELS = {"none": "No production impact", "prod-safe": "Production, no downtime",
                 "deploys": "Deploys to production", "downtime": "Needs downtime"}


def server_projects(ip, ctx):
    srv = ctx["servers"].get(ip, {})
    names = [n.lower() for n in srv.get("names", [])] + [h["alias"].lower() for h in ctx["hosts"].get(ip, [])]
    units = [u.lower() for u in srv.get("units", [])]
    out = []
    for repo, r in ctx["repos"].items():
        short = repo.split("/")[-1].lower()
        if ip in r.get("hosts", []) or (len(short) >= 4 and any(short in n for n in names + units)):
            out.append(repo)
    return sorted(out)


def repo_is_production(repo, ctx):
    r = ctx["repos"].get(repo) or {}
    return bool(r.get("deploys")) or any(repo in server_projects(ip, ctx) for ip in ctx["servers"])


def server_entry(ip, ctx):
    hs = ctx["hosts"].get(ip, [])
    alias = ctx["servers"].get(ip, {}).get("alias") or (hs[0]["alias"] if hs else ip)
    projects = server_projects(ip, ctx)
    return {"name": "%s server (%s)" % (alias, ip), "production": True,
            "detail": ("runs " + ", ".join(projects)) if projects else "projects on it not identified"}


def repo_entry(repo, ctx):
    r = ctx["repos"].get(repo) or {}
    prod = repo_is_production(repo, ctx)
    detail = []
    if r.get("deploys"):
        detail.append("deploys with " + ", ".join(os.path.basename(d) for d in r["deploys"][:3]))
    for ip in r.get("hosts", []):
        detail.append("to " + server_entry(ip, ctx)["name"])
    return {"name": repo, "production": prod, "detail": "; ".join(detail)}


def where_of(g, fs, ctx):
    kind, scope = g["kind"], g["scope"]
    if kind.startswith("server"):
        return [server_entry(scope, ctx)]
    if kind == "key":
        out = []
        for f in fs:
            for dest in re.findall(r"[\w.-]+@([\w-]+(?:\.[\w-]+)*)", f["detail"]):
                if dest == "github.com":
                    out.append({"name": "GitHub", "production": False,
                                "detail": "every repository this key can push to"})
                else:
                    try:
                        ip = socket.gethostbyname(dest)
                    except OSError:
                        ip = dest
                    out.append(server_entry(ip, ctx))
        uniq = {e["name"]: e for e in out}
        return list(uniq.values()) or [{"name": "This Mac", "production": False, "detail": "key not used in ssh config"}]
    if kind in ("secrets", "deps", "workflows", "repo-settings", "secrets-github"):
        if "/" in scope and not scope.startswith("~"):
            return [repo_entry(scope, ctx)]
        return [{"name": scope, "production": False, "detail": "local folder with no GitHub remote"}]
    if kind in ("org-2fa", "org-settings"):
        n = sum(1 for r in ctx["repos"] if r.split("/")[0].lower() == scope.lower())
        return [{"name": "%s organization" % scope, "production": False, "detail": "%d repositories" % n}]
    if kind == "github-review":
        repo = repo_of(fs[0]["target"])
        if "/" in repo:
            return [repo_entry(repo, ctx)]
        return [{"name": "%s organization" % repo.split("|")[0], "production": False, "detail": ""}]
    if kind in ("github-plan",):
        return [{"name": "GitHub plan", "production": False, "detail": ""}]
    return [{"name": "This Mac", "production": False, "detail": "Claude Code and macOS settings"
             if kind.startswith("claude") else "macOS"}]


def impact_of(g, fs, ctx):
    """(level, text): what the fix does to production systems while it is applied."""
    kind = g["kind"]
    checks = {f["check"] for f in fs}
    where = g["where"]
    prod_names = [w["name"] for w in where if w["production"]]
    repo = g["scope"] if "/" in g["scope"] and not g["scope"].startswith("~") else None
    deploys = (ctx["repos"].get(repo) or {}).get("deploys") if repo else None
    if kind == "server-ssh":
        return "prod-safe", ("No downtime. Reloading SSH keeps open sessions and does not touch the apps; only new "
                             "SSH logins are affected, and the checks prove they still work.")
    if kind == "server-patch":
        if "reboot" in checks or "security-updates" in checks:
            return "downtime", ("About 1 to 3 minutes offline while %s reboots: %s. Schedule a quiet window." % (
                where[0]["name"], where[0]["detail"]))
        return "prod-safe", "No downtime expected; each service restarts for a few seconds during the upgrade."
    if kind == "server-firewall":
        return "prod-safe", ("No downtime if the allowed ports are right; the checks confirm every port that "
                             "answered before still answers.")
    if kind == "server-incident":
        return "downtime", "Likely: cleaning up usually means rebuilding the server from a clean deploy."
    if kind == "key":
        return "none", ("No effect on running services; only how this Mac logs in changes. Jobs on this Mac that use "
                        "the key need it unlocked after a restart.")
    if kind in ("secrets", "deps", "workflows"):
        if deploys:
            what = {"secrets": "Merging the cleanup pull request runs %s, a normal deploy with no functional change. "
                               "Rotating a real secret causes a short window of failed calls to that service unless "
                               "the new value is set before the old one is revoked.",
                    "deps": "Each merged update deploys to production through %s; CI must pass first, and a bad "
                            "update is undone by reverting the merge.",
                    "workflows": "Changes the pipeline that deploys to production (%s); the next deploy after the "
                                 "merge is watched."}[kind]
            return "deploys", what % ", ".join(os.path.basename(d) for d in deploys[:3])
        if prod_names:
            return "prod-safe", "Production code, but no deploy runs on merge; the change ships with your next deploy."
        return "none", "No production deploy is connected to this repository."
    if kind == "repo-settings":
        if "deploy-key-write" in checks:
            return "prod-safe", "No downtime, unless a server or job pushes with that deploy key; find it first."
        return "none", "Repository settings only; code and deploys are unchanged."
    if kind == "org-2fa":
        return "none", "No downtime; members without two-factor login lose access, which can stop CI that uses their tokens."
    if kind == "server-review":
        return "none", "Nothing changes unless you remove an item; removing one stops only what it does."
    return "none", "No production systems involved."


BUILDERS = {"key": build_key, "server-ssh": build_server, "server-patch": build_server,
            "server-firewall": build_server, "server-incident": build_server, "server-review": build_server,
            "secrets": build_secrets, "deps": build_repo, "workflows": build_repo, "repo-settings": build_repo}


def build_groups(rep):
    """Group the open findings of a report; return groups ordered by severity."""
    findings = [f for f in rep.get("findings", []) if f["severity"] != "info"]
    checkouts = {checkout_of(f) for f in findings if f["area"] in ("secrets", "supply")}
    remotes = {co: remote_of(co) for co in checkouts if co.startswith("~")}
    ctx = {"servers": (rep.get("context") or {}).get("servers", {}), "hosts": hosts_by_ip(), "remotes": remotes,
           "repos": (rep.get("context") or {}).get("repos", {})}
    by = {}
    for f in findings:
        kind, scope = classify(f, remotes)
        by.setdefault((kind, scope), []).append(f)
    records = load_records()
    groups = []
    for (kind, scope), fs in by.items():
        if kind.startswith("server"):
            hs = ctx["hosts"].get(scope, [])
            name = next((h["alias"] for h in hs if h["user"] == "root"), hs[0]["alias"] if hs else scope)
        elif kind.startswith(("key", "secrets")):
            name = os.path.basename(scope.rstrip("/"))
        else:
            name = scope
        gid = slug("%s-%s" % (kind, name))
        g = {"id": gid, "kind": kind, "scope": scope, "finding_ids": [f["id"] for f in fs],
             "severity": min((f["severity"] for f in fs), key=lambda s: sa.SEV_ORDER[s]),
             "command": "/security-audit fix-group %s" % gid, "checks": []}
        BUILDERS.get(kind, build_other)(g, fs, ctx)
        g["where"] = where_of(g, fs, ctx)
        level, text = impact_of(g, fs, ctx)
        g["impact"] = {"level": level, "label": IMPACT_LABELS[level], "text": text}
        prs = sorted({f["remedy"]["url"] for f in fs if (f.get("remedy") or {}).get("status") in
                      ("pr-open", "pr-opened") and f["remedy"].get("url")})
        if prs:
            g["prs"] = prs
        if records.get(gid):
            g["last"] = records[gid][-1]
        groups.append(g)
    seen = {}
    for g in groups:  # keep ids unique when two scopes slug alike
        n = seen.get(g["id"], 0)
        seen[g["id"]] = n + 1
        if n:
            g["id"] += "-%d" % (n + 1)
            g["command"] = "/security-audit fix-group %s" % g["id"]
    groups.sort(key=lambda g: (sa.SEV_ORDER[g["severity"]], -len(g["finding_ids"]), g["title"]))
    return groups


# ---------------------------------------------------------------------------- connectivity checks

def run_check(c):
    """Return {"ok": bool, "value": comparable value, "detail": text}."""
    t = c["type"]
    if t == "ssh":
        rc, _, err = sa.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", c["alias"], "true"], 30)
        return {"ok": rc == 0, "value": rc == 0, "detail": "ok" if rc == 0 else (err.strip().splitlines() or ["?"])[-1]}
    if t == "github-ssh":
        rc, _, err = sa.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "IdentitiesOnly=yes",
                             "-i", c["key"], "-T", "git@github.com"], 30)
        ok = "successfully authenticated" in err
        return {"ok": ok, "value": ok, "detail": "ok" if ok else (err.strip().splitlines() or ["?"])[-1]}
    if t == "tcp":
        try:
            with socket.create_connection((c["host"], int(c["port"])), timeout=5):
                return {"ok": True, "value": True, "detail": "open"}
        except (OSError, ValueError) as e:
            return {"ok": False, "value": False, "detail": str(e)[:100]}
    if t == "http":
        rc, out, _ = sa.run(["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "10", c["url"]], 20)
        code = out.strip() or "000"
        return {"ok": code != "000", "value": code != "000", "detail": "HTTP %s" % code}
    if t == "units":
        rc, out, err = sa.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", c["alias"],
                               "systemctl --failed --no-legend --plain | awk '{print $1}'"], 40)
        failed = sorted(l for l in out.split() if l)
        return {"ok": rc == 0, "value": failed, "detail": ("failed: " + ", ".join(failed)) if failed else
                ("none failed" if rc == 0 else "could not connect")}
    if t == "ci":
        st, info = sa.gh("repos/%s" % c["repo"])
        branch = (info or {}).get("default_branch", "main")
        rc, out, _ = sa.run(["gh", "run", "list", "-R", c["repo"], "-b", branch, "-L", "30", "--json",
                             "workflowName,conclusion,status"], 40)
        latest = {}
        for r in json.loads(out) if rc == 0 and out.strip() else []:
            if r.get("status") == "completed":
                latest.setdefault(r["workflowName"], r["conclusion"])
        bad = sorted(w for w, s in latest.items() if s not in ("success", "skipped", "neutral"))
        return {"ok": rc == 0 and not bad, "value": latest,
                "detail": ("failing: " + ", ".join(bad)) if bad else "%d workflows passing" % len(latest)}
    return {"ok": False, "value": None, "detail": "unknown check"}


def check_key(c):
    return "%s:%s" % (c["type"], c.get("alias") or c.get("key") or c.get("url") or c.get("repo") or
                      "%s:%s" % (c.get("host"), c.get("port")))


def snapshot(group):
    return {"group": group["id"], "taken": sa.now_iso(),
            "results": {check_key(c): dict(run_check(c), label=c["label"]) for c in group["checks"]}}


def compare(before, after):
    """Return (regressions, recovered, unchanged): lists of (label, before detail, after detail)."""
    reg, rec, same = [], [], []
    for k, a in after["results"].items():
        b = before["results"].get(k)
        if b is None:
            continue
        row = (a["label"], b["detail"], a["detail"])
        if isinstance(a["value"], list):  # failed services: any newly failed one is a regression
            (reg if set(a["value"]) - set(b["value"] or []) else rec if set(b["value"] or []) - set(a["value"])
             else same).append(row)
        elif isinstance(a["value"], dict):  # CI: a workflow that passed before and fails now
            newly = [w for w, s in a["value"].items() if s not in ("success", "skipped", "neutral") and
                     (b["value"] or {}).get(w) in ("success", "skipped", "neutral")]
            (reg if newly else same).append(row)
        elif b["ok"] and not a["ok"]:
            reg.append(row)
        elif a["ok"] and not b["ok"]:
            rec.append(row)
        else:
            same.append(row)
    return reg, rec, same


# ---------------------------------------------------------------------------- fix records

def load_records():
    return sa.load_json(FIXES_FILE, {})


def record(gid, status, note):
    recs = load_records()
    recs.setdefault(gid, []).append({"status": status, "note": note, "on": sa.now_iso()})
    sa.write_json(FIXES_FILE, recs)
