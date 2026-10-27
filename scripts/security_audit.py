#!/usr/bin/env python3
"""Weekly security audit across this Mac, its SSH keys, local checkouts, GitHub orgs, servers and Claude plugins.

The scan is read-only: it never changes a setting, a file outside its own state folder, a server or GitHub. Every
finding carries a severity, a stable id (so a week-to-week diff can say what is new) and the fix. Accepted risks are
listed in ~/.security-audit/accepted.json and reported apart from the open findings.

With --fix, the scan then makes the GitHub fixes that cannot break a repository (security_fix.py lists them):
settings that only add alerts or block force pushes, and pull requests that pin actions. It never merges.

Usage:
    security_audit.py scan [--only AREA,...] [--skip AREA,...] [--quick] [--full-history] [--lynis] [--fix]
                           [--html PAGE] [--json OUT] [--md OUT]
    security_audit.py fix [--dry-run]       (fixes from the latest report, without a new scan)
    security_audit.py accept FINDING_ID "reason" [--days 90]
    security_audit.py tools

Areas: mac, keys, secrets, supply, github, servers, claude.
"""
import argparse
import concurrent.futures
import datetime
import fnmatch
import glob
import hashlib
import html
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

VERSION = "0.2.3"
HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".security-audit")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
ACCEPTED_FILE = os.path.join(STATE_DIR, "accepted.json")
LOCK_FILE = os.path.join(STATE_DIR, "lock")
HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "server_probe.sh")
REPORTS_DIR = os.path.join(STATE_DIR, "reports")
# scanners installed with `go install` or `uv tool install`, which a scheduled task's PATH may not include
for _d in (os.path.join(HOME, ".local", "bin"), os.path.join(HOME, "go", "bin")):
    if os.path.isdir(_d) and _d not in os.environ.get("PATH", "").split(os.pathsep):
        os.environ["PATH"] = os.environ.get("PATH", "") + os.pathsep + _d

AREAS = ["mac", "keys", "secrets", "supply", "github", "servers", "claude"]
AREA_TITLES = {
    "mac": "This Mac",
    "keys": "SSH keys",
    "secrets": "Secrets on disk",
    "supply": "Supply chain (dependencies)",
    "github": "GitHub orgs and repos",
    "servers": "Servers",
    "claude": "Claude Code plugins, hooks and permissions",
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SKIP_DIRS = {"node_modules", ".git", "Library", ".Trash", ".cache", ".npm", ".gradle", ".cocoapods", "Pods",
             "DerivedData", ".venv", "venv", "__pycache__", ".next", "dist", "build", ".build", ".swiftpm",
             ".android", ".tart", "Applications", "Movies", "Music", "Pictures"}
OFFICIAL_MARKETPLACES = {"anthropics/claude-plugins-official"}
FIRST_PARTY_ACTION_OWNERS = {"actions", "github"}
HIDDEN_UNICODE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]")
INJECTION_PHRASES = re.compile(
    r"ignore (all |any )?(previous|prior|above) instructions|do not (tell|inform|show) the user|"
    r"without (asking|telling) the user|disregard (your|the) (rules|instructions)|you are now in (developer|god) mode",
    re.I)
EXFIL_PATTERNS = re.compile(
    r"(curl|wget)[^\n|]*\|\s*(ba|z)?sh\b|base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh|"
    r"(discord(app)?\.com/api/webhooks|webhook\.site|ngrok\.io|ngrok-free\.app|pastebin\.com|transfer\.sh|requestbin\.)|"
    r"(cat|cp|tar|zip)[^\n]*(\.ss[h]/id_|\.aw[s]/credentials|\.npm[r]c|\.git-credential[s]|Keychain[s])",
    re.I)
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|mocks?|e2e)/|\.(test|spec|e2e)\.\w+$|_test\.\w+$", re.I)
SHAI_HULUD_FILES = {"setup_bun.js", "bun_environment.js", "shai-hulud-workflow.yml", "truffleSecrets.json"}
MINER_NAMES = re.compile(r"xmrig|kdevtmpfsi|kinsing|minerd|cryptonight", re.I)
WEB_PORTS = {"22", "80", "443"}


# ---------------------------------------------------------------------------- helpers

def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def run(cmd, timeout=60, input=None, cwd=None, env=None):
    """Run a command; return (returncode, stdout, stderr). Never raises for a failing or missing command."""
    try:
        p = subprocess.run(cmd, input=input, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env,
                           stdin=None if input is not None else subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", "not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out after %ss" % timeout
    except Exception as e:  # noqa: BLE001 - a probe must never stop the audit
        return 1, "", str(e)


def have(tool):
    return shutil.which(tool) is not None


def read_text(path, limit=2_000_000):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def sha(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def hash_tree(root, limit=4000):
    """Content hash of a folder (file paths and bytes), to tell whether an installed plugin changed."""
    h = hashlib.sha256()
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in {".git", "node_modules", "__pycache__"})
        for name in sorted(filenames):
            p = os.path.join(dirpath, name)
            try:
                with open(p, "rb") as f:
                    h.update(os.path.relpath(p, root).encode())
                    h.update(f.read(1_000_000))
            except OSError:
                continue
            n += 1
            if n >= limit:
                return h.hexdigest()[:16]
    return h.hexdigest()[:16]


class Audit:
    def __init__(self, args):
        self.args = args
        self.findings = []
        self.notes = []          # coverage gaps: what could not be checked and why
        self.inventory = {}      # counts of what was looked at, per area
        self.prev = load_json(STATE_FILE, {})
        self.baseline_prev = self.prev.get("baseline", {})
        self.baseline = {}
        self.first_run = not self.prev
        self.accepted = load_json(ACCEPTED_FILE, {})

    # findings ------------------------------------------------------------------

    def add(self, area, severity, check, target, title, detail="", fix=""):
        fid = "%s:%s:%s" % (area, check, target)
        if any(f["id"] == fid for f in self.findings):
            return
        self.findings.append({
            "id": fid, "area": area, "severity": severity, "check": check, "target": target,
            "title": title, "detail": detail, "fix": fix,
        })

    def note(self, area, text):
        self.notes.append({"area": area, "text": text})

    def count(self, area, key, n=1):
        self.inventory.setdefault(area, {})
        self.inventory[area][key] = self.inventory[area].get(key, 0) + n

    def diff_baseline(self, key, items):
        """Record `items` (a set of strings) under `key`; return the ones not seen last run (None on first sight)."""
        items = set(items)
        self.baseline[key] = sorted(items)
        if key not in self.baseline_prev:
            return None
        return sorted(items - set(self.baseline_prev[key]))

    def removed_since(self, key, items):
        if key not in self.baseline_prev:
            return []
        return sorted(set(self.baseline_prev[key]) - set(items))


# ---------------------------------------------------------------------------- ssh config

def parse_ssh_config(path=None, seen=None):
    """Return a list of {'aliases': [...], 'hostname', 'user', 'port', 'identityfiles': [...]} host blocks."""
    path = path or os.path.join(HOME, ".ssh", "config")
    seen = seen if seen is not None else set()
    if path in seen or not os.path.isfile(path):
        return []
    seen.add(path)
    blocks, cur = [], None
    for raw in (read_text(path) or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"\s+|=", line, maxsplit=1)
        key = parts[0].lower()
        val = parts[1].strip() if len(parts) > 1 else ""
        if key == "include":
            for pat in val.split():
                pat = os.path.expanduser(pat)
                if not os.path.isabs(pat):
                    pat = os.path.join(HOME, ".ssh", pat)
                for inc in sorted(glob.glob(pat)):
                    blocks.extend(parse_ssh_config(inc, seen))
            continue
        if key == "host":
            cur = {"aliases": val.split(), "hostname": None, "user": None, "port": "22", "identityfiles": []}
            blocks.append(cur)
            continue
        if key == "match":
            cur = None
            continue
        if cur is None:
            continue
        if key == "hostname":
            cur["hostname"] = val
        elif key == "user":
            cur["user"] = val
        elif key == "port":
            cur["port"] = val
        elif key == "identityfile":
            cur["identityfiles"].append(os.path.realpath(os.path.expanduser(val.strip('"'))))
    return blocks


def ssh_hosts():
    """Concrete server entries from ssh config (no wildcards, no git forges), one per alias."""
    out = []
    for b in parse_ssh_config():
        for a in b["aliases"]:
            if any(c in a for c in "*?!"):
                continue
            hn = b["hostname"] or a
            if re.search(r"(^|\.)(github\.com|gitlab\.com|bitbucket\.org|ssh\.dev\.azure\.com)$", hn):
                continue
            out.append({"alias": a, "hostname": hn, "user": b["user"] or os.environ.get("USER", ""),
                        "port": b["port"], "identityfiles": b["identityfiles"]})
    return out


# ---------------------------------------------------------------------------- area: mac

def check_mac(a):
    if platform.system() != "Darwin":
        a.note("mac", "Not a Mac: macOS checks skipped.")
        return
    area = "mac"
    rc, out, _ = run(["fdesetup", "status"])
    if "FileVault is On" not in out:
        a.add(area, "critical", "filevault", "disk", "FileVault disk encryption is off",
              out.strip(), "System Settings > Privacy & Security > FileVault > Turn On.")
    rc, out, _ = run(["csrutil", "status"])
    if "enabled" not in out:
        a.add(area, "critical", "sip", "system", "System Integrity Protection is disabled", out.strip(),
              "Boot to Recovery and run `csrutil enable`.")
    rc, out, _ = run(["spctl", "--status"])
    if "enabled" not in out:
        a.add(area, "high", "gatekeeper", "system", "Gatekeeper is disabled", out.strip(),
              "Run `sudo spctl --master-enable`.")
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    rc, out, _ = run([fw, "--getglobalstate"])
    if "enabled" not in out.lower():
        a.add(area, "high", "firewall", "system", "The macOS application firewall is off", out.strip(),
              "System Settings > Network > Firewall > On.")
    rc, out, _ = run([fw, "--getstealthmode"])
    if "off" in out.lower():
        a.add(area, "low", "stealth", "system", "Firewall stealth mode is off",
              "The Mac answers pings and probes on closed ports.",
              "System Settings > Network > Firewall > Options > Enable stealth mode.")
    rc, out, _ = run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate",
                      "AutomaticallyInstallMacOSUpdates"])
    if out.strip() != "1":
        a.add(area, "medium", "autoupdate", "system", "macOS updates are not installed automatically", "",
              "System Settings > General > Software Update > Automatic updates > Install macOS updates.")
    if not a.args.quick:
        rc, out, err = run(["softwareupdate", "-l"], timeout=180)
        pending = [l.strip()[2:] for l in out.splitlines() if l.strip().startswith("* Label:")]
        if pending:
            a.add(area, "medium", "pending-updates", "system", "%d macOS software update(s) waiting" % len(pending),
                  "; ".join(pending[:6]), "Install them from System Settings > General > Software Update.")

    rc, out, _ = run(["launchctl", "print-disabled", "system"])
    sharing = {"com.openssh.sshd": "Remote Login (SSH server)", "com.apple.smbd": "File Sharing (SMB)",
               "com.apple.screensharing": "Screen Sharing"}
    for label, name in sharing.items():
        m = re.search(r'"%s" => (\w+)' % re.escape(label), out)
        if m and m.group(1) == "enabled":
            sev = "medium" if "sshd" in label or "screensharing" in label else "low"
            a.add(area, sev, "sharing", label, "%s is turned on" % name,
                  "Anyone on the same network can try to log in to this Mac.",
                  "Turn it off in System Settings > General > Sharing unless you use it; if you keep SSH, allow "
                  "key logins only.")

    rc, out, _ = run(["netstat", "-an", "-p", "tcp"])
    exposed = set()
    for line in out.splitlines():
        if "LISTEN" not in line:
            continue
        local = line.split()[3]
        host, _, port = local.rpartition(".")
        if host in ("*", "0.0.0.0", "::", "*.*") or host.startswith("*"):
            exposed.add(port)
    if exposed:
        a.count(area, "listening ports on all interfaces", len(exposed))
        new = a.diff_baseline("mac.listen", exposed)
        if new:
            a.add(area, "medium", "new-listener", ",".join(new),
                  "New network listener(s) on all interfaces: port %s" % ", ".join(new),
                  "These ports were not listening last week.",
                  "Find the process with `sudo lsof -nP -iTCP:<port> -sTCP:LISTEN` and confirm it is expected.")

    edr_paths = {"/Library/Sentinel": "SentinelOne", "/Applications/Falcon.app": "CrowdStrike Falcon",
                 "/Library/CS": "CrowdStrike Falcon", "/Applications/Microsoft Defender.app": "Microsoft Defender",
                 "/Library/Application Support/JAMF/Jamf Protect": "Jamf Protect",
                 "/Applications/Malwarebytes.app": "Malwarebytes"}
    found = [v for k, v in edr_paths.items() if os.path.exists(k)]
    if found:
        a.inventory.setdefault(area, {})["endpoint protection"] = ", ".join(sorted(set(found)))
    else:
        a.add(area, "medium", "edr", "system", "No endpoint malware protection found",
              "No SentinelOne, CrowdStrike, Defender, Jamf Protect or Malwarebytes install was found.",
              "Install an endpoint protection agent; it is the main defence against malware on the Mac itself.")

    check_launch_items(a)
    check_startup_files(a)


def signer(path):
    rc, out, err = run(["codesign", "-dvv", path], timeout=20)
    text = out + err
    if "Permission denied" in text:
        return "unreadable"
    if "not signed" in text or rc != 0:
        return None
    m = re.search(r"^Authority=(.+)$", text, re.M)
    team = re.search(r"^TeamIdentifier=(.+)$", text, re.M)
    if "Signature=adhoc" in text:
        return "adhoc"
    return (m.group(1) if m else "signed") + (" (%s)" % team.group(1) if team and team.group(1) != "not set" else "")


def check_launch_items(a):
    area = "mac"
    dirs = [os.path.join(HOME, "Library/LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    items = {}
    for d in dirs:
        for plist in sorted(glob.glob(os.path.join(d, "*.plist"))):
            rc, out, _ = run(["plutil", "-convert", "json", "-o", "-", plist])
            try:
                data = json.loads(out)
            except ValueError:
                data = {}
            args = data.get("ProgramArguments") or []
            prog = data.get("Program") or (args[0] if args else "")
            items[plist] = (prog, args)
    a.count(area, "launch agents and daemons", len(items))
    keys = set()
    for plist, (prog, args) in items.items():
        keys.add("%s -> %s" % (plist, prog))
        if not prog:
            continue
        interp = os.path.basename(prog) in {"bash", "sh", "zsh", "python", "python3", "osascript", "node", "perl",
                                            "ruby", "curl"}
        odd_place = re.match(r"^(/tmp|/private/tmp|/var/tmp|/Users/Shared|%s/\.)" % re.escape(HOME), prog)
        target = args[1] if interp and len(args) > 1 else prog
        if interp or odd_place:
            a.add(area, "high", "launch-script", plist,
                  "Startup item runs a script or a program from an unusual place",
                  "%s runs: %s" % (os.path.basename(plist), " ".join(args)[:300] or prog),
                  "Malware commonly persists this way. Confirm you installed it; otherwise unload it with "
                  "`launchctl bootout` and delete the plist.")
            continue
        if not os.path.exists(prog):
            continue
        who = signer(target)
        if who == "unreadable":
            continue
        if who is None or who == "adhoc":
            a.add(area, "medium", "launch-unsigned", plist,
                  "Startup item runs %s code" % ("ad-hoc signed" if who else "unsigned"),
                  "%s -> %s" % (os.path.basename(plist), prog),
                  "Confirm which app installed it. Signed vendor software is the norm.")
    new = a.diff_baseline("mac.launch", keys)
    for k in new or []:
        a.add(area, "high", "launch-new", k.split(" -> ")[0], "New startup item since the last audit",
              k, "Confirm you installed this. New launch agents are the usual sign of Mac malware.")


def check_startup_files(a):
    area = "mac"
    files = [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".ssh/config",
             ".gitconfig", ".npmrc"]
    hashes = {}
    for rel in files:
        p = os.path.join(HOME, rel)
        text = read_text(p)
        if text is None:
            continue
        hashes[rel] = sha(text)
        if rel != ".ssh/config" and EXFIL_PATTERNS.search(text):
            a.add(area, "high", "rc-suspicious", rel, "Shell or tool start-up file runs a downloaded script",
                  "~/%s matches a download-and-run or credential-copy pattern." % rel,
                  "Read the file and remove anything you did not add.")
    for p in ["/etc/hosts"]:
        text = read_text(p)
        if text is not None:
            hashes[p] = sha(text)
    prev = a.baseline_prev.get("mac.startup-files")
    a.baseline["mac.startup-files"] = hashes
    if isinstance(prev, dict):
        for k, v in hashes.items():
            if k in prev and prev[k] != v:
                a.add(area, "medium", "rc-changed", k, "Start-up or config file changed since the last audit",
                      "%s changed. Expected if you edited it yourself." % k,
                      "Review the change (`git diff` is not available here; compare with a backup or Time Machine).")


# ---------------------------------------------------------------------------- area: keys

PRIVATE_KEY_HEAD = re.compile(r"-----BEGIN (OPENSSH|RSA|DSA|EC|ENCRYPTED)? ?PRIVATE KEY-----")


def check_keys(a):
    area = "keys"
    sshdir = os.path.join(HOME, ".ssh")
    candidates = set()
    for p in glob.glob(os.path.join(sshdir, "*")) + glob.glob(os.path.join(sshdir, "*", "*")):
        if os.path.isfile(p) and not p.endswith(".pub"):
            head = read_text(p, 200) or ""
            if PRIVATE_KEY_HEAD.search(head):
                candidates.add(os.path.realpath(p))
    hosts = ssh_hosts()
    for h in hosts:
        for f in h["identityfiles"]:
            if os.path.isfile(f):
                candidates.add(f)
    uses = {}
    for b in parse_ssh_config():
        for f in b["identityfiles"]:
            for al in b["aliases"]:
                uses.setdefault(f, set()).add("%s@%s" % (b["user"] or "?", b["hostname"] or al))
    a.count(area, "private keys", len(candidates))
    for key in sorted(candidates):
        name = key.replace(HOME, "~")
        mode = stat.S_IMODE(os.stat(key).st_mode)
        if mode & 0o077:
            a.add(area, "high", "key-perms", name, "Private key is readable by other accounts",
                  "%s has mode %o." % (name, mode), "Run `chmod 600 %s`." % name)
        rc, _, _ = run(["ssh-keygen", "-y", "-P", "", "-f", key], timeout=10)
        opens = sorted(uses.get(key, []))
        if rc == 0:
            root = any(o.startswith("root@") for o in opens)
            forge = any("github.com" in o for o in opens)
            sev = "high" if root or forge or not opens else "medium"
            a.add(area, sev, "no-passphrase", name, "SSH private key has no passphrase",
                  ("Opens: %s." % ", ".join(opens)) if opens else "Not referenced in ~/.ssh/config.",
                  "Anyone or any malware that copies this file gets that access. Add a passphrase with "
                  "`ssh-keygen -p -f %s` and keep it in the macOS keychain (`UseKeychain yes`, "
                  "`AddKeysToAgent yes`), or move the key into a hardware/Secure Enclave key or 1Password/"
                  "Bitwarden SSH agent. For an unattended bot key, restrict it on the server "
                  "(`from=`, `command=`, `restrict` in authorized_keys) and accept the risk." % name)
        rc, out, _ = run(["ssh-keygen", "-l", "-f", key], timeout=10)
        m = re.match(r"(\d+) \S+ .*\((\w+)\)", out.strip())
        if m:
            bits, kind = int(m.group(1)), m.group(2)
            if kind == "DSA" or (kind == "RSA" and bits < 3072):
                a.add(area, "medium", "weak-key", name, "Weak SSH key (%s %d bits)" % (kind, bits), "",
                      "Replace with `ssh-keygen -t ed25519` and remove the old public key from servers and GitHub.")
        age_days = (datetime.datetime.now().timestamp() - os.stat(key).st_mtime) / 86400
        if age_days > 730:
            a.add(area, "low", "old-key", name, "SSH key is over two years old", "",
                  "Rotate keys periodically, starting with ones that reach production.")
    auth = os.path.join(sshdir, "authorized_keys")
    if os.path.isfile(auth):
        rc, out, _ = run(["ssh-keygen", "-lf", auth])
        fps = {l.split()[1] + " " + " ".join(l.split()[2:]) for l in out.splitlines() if len(l.split()) > 1}
        a.count(area, "keys allowed to log in to this Mac", len(fps))
        for k in a.diff_baseline("keys.mac-authorized", fps) or []:
            a.add(area, "high", "mac-authkey-new", k.split()[0], "New key allowed to log in to this Mac", k,
                  "Remove it from ~/.ssh/authorized_keys unless you added it.")


# ---------------------------------------------------------------------------- local checkouts

def find_checkouts(roots, max_depth=4):
    """Main checkouts (one per repository, worktrees folded into their repository)."""
    found = {}
    def walk(d, depth):
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        names = {e.name for e in entries}
        if ".git" in names:
            gitp = os.path.join(d, ".git")
            if os.path.isdir(gitp):
                found.setdefault(os.path.realpath(gitp), d)
            else:
                rc, out, _ = run(["git", "-C", d, "rev-parse", "--path-format=absolute", "--git-common-dir"], 10)
                if rc == 0:
                    found.setdefault(os.path.realpath(out.strip()), d)
            return
        if depth >= max_depth:
            return
        for e in entries:
            if e.is_dir(follow_symlinks=False) and e.name not in SKIP_DIRS and not e.name.startswith("."):
                walk(e.path, depth + 1)
    for r in roots:
        walk(r, 0)
    return sorted(set(found.values()))


def checkout_roots():
    roots = [HOME]
    return [r for r in roots if os.path.isdir(r)]


# ---------------------------------------------------------------------------- area: secrets

CRED_NAMES = ["*.pem", "*.p12", "*.pfx", "*.key", "*.ovpn", "*.keystore", "*.jks", ".netrc", ".git-credentials",
              ".pypirc", "credentials", "*service-account*.json", "*serviceAccount*.json", "*.mobileprovision"]


def check_secrets(a, checkouts):
    area = "secrets"
    # loose credential files in the home folder
    hits = []
    def walk(d, depth):
        try:
            entries = list(os.scandir(d))
        except OSError:
            return
        for e in entries:
            if e.is_dir(follow_symlinks=False):
                if depth < 4 and e.name not in SKIP_DIRS and e.name not in {"sessions", "file-history", "projects",
                                                                             "plugins"}:
                    walk(e.path, depth + 1)
            elif e.is_file(follow_symlinks=False) and any(fnmatch.fnmatch(e.name, p) for p in CRED_NAMES):
                hits.append(e.path)
    walk(HOME, 0)
    for p in [os.path.join(HOME, ".aws/credentials"), os.path.join(HOME, ".docker/config.json"),
              os.path.join(HOME, ".config/gcloud/application_default_credentials.json")]:
        if os.path.isfile(p):
            hits.append(p)
    a.count(area, "credential files found", len(hits))
    for p in sorted(set(hits)):
        name = p.replace(HOME, "~")
        mode = stat.S_IMODE(os.stat(p).st_mode)
        if mode & 0o044:
            a.add(area, "high", "cred-perms", name, "Credential file readable by other accounts",
                  "%s has mode %o." % (name, mode), "Run `chmod 600 '%s'`." % name)
        if os.path.basename(p) == ".git-credentials":
            a.add(area, "medium", "git-credentials", name, "Git passwords/tokens stored in plain text",
                  name, "Use `gh auth setup-git` or the osxkeychain helper, then delete the file.")
    npmrc = read_text(os.path.join(HOME, ".npmrc")) or ""
    if re.search(r"_authToken\s*=\s*(?!\$\{)", npmrc):
        a.add(area, "medium", "npm-token", "~/.npmrc", "npm publish token stored in ~/.npmrc",
              "npm worms (Shai-Hulud) steal exactly this token to publish infected versions of your packages.",
              "Use a short-lived granular token with 2FA-for-publish, or log out with `npm logout` when not "
              "publishing.")
    if "ignore-scripts" not in npmrc:
        a.add(area, "low", "npm-scripts", "~/.npmrc", "npm runs package install scripts by default",
              "Install scripts are how most malicious npm packages execute on install.",
              "Consider `npm config set ignore-scripts true` and allow-listing the few packages that need them "
              "(or use pnpm, which blocks them by default).")

    # tracked .env files and committed secrets
    leaks_tool = "betterleaks" if have("betterleaks") else ("gitleaks" if have("gitleaks") else None)
    if not leaks_tool:
        a.note(area, "gitleaks is not installed, so commit history was not scanned for secrets "
                     "(`brew install gitleaks`).")
    scanned = a.prev.get("leaks-scanned", {})
    a.baseline.setdefault("_leaks", {})
    for co in checkouts:
        rc, out, _ = run(["git", "-C", co, "ls-files"], timeout=30)
        envs = [f for f in out.splitlines() if re.search(r"(^|/)\.env(\.[\w-]+)?$", f)
                and not re.search(r"\.(example|sample|template|dist|defaults?)$", f)]
        for f in envs[:10]:
            a.add(area, "high", "env-tracked", "%s/%s" % (co.replace(HOME, "~"), f), "An .env file is committed to git",
                  "%s in %s" % (f, co.replace(HOME, "~")),
                  "Rotate every secret in it, `git rm --cached` it, add it to .gitignore.")
        if not leaks_tool:
            continue
        rc, head, _ = run(["git", "-C", co, "rev-parse", "HEAD"], 10)
        head = head.strip()
        first = co not in scanned or a.args.full_history
        report = tempfile.NamedTemporaryFile(prefix="leaks-", suffix=".json", delete=False).name
        cmd = [leaks_tool, "git", co, "--redact", "--no-banner", "--exit-code", "0",
               "--report-format", "json", "--report-path", report]
        if not first:
            cmd += ["--log-opts", "--all --since=%s" % scanned[co].get("date", "8 days ago")]
        run(cmd, timeout=900)
        found = load_json(report, [])
        try:
            os.unlink(report)
        except OSError:
            pass
        a.count(area, "repositories scanned for committed secrets")
        # the weekly scan reads only new commits, so keep last runs' hits until they are accepted
        hits = {} if first else {h["target"]: h for h in scanned[co].get("hits", [])}
        for leak in found[:50]:
            loc = "%s:%s" % (leak.get("File"), leak.get("StartLine"))
            in_test = bool(TEST_PATH.search(leak.get("File") or ""))
            target = "%s/%s:%s" % (co.replace(HOME, "~"), leak.get("RuleID"), loc)
            commits = (hits.get(target) or {}).get("commits", 0) + 1
            hits[target] = {"target": target, "severity": "low" if in_test else "high", "commits": commits,
                            "title": "Secret committed to git (%s)%s" % (leak.get("RuleID"),
                                                                          " in a test file" if in_test else ""),
                            "detail": "%s at %s, %s by %s" % (
                                co.replace(HOME, "~"), loc, "commit %s" % (leak.get("Commit") or "")[:10]
                                if commits == 1 else "in %d commits" % commits, leak.get("Author"))}
        a.baseline["_leaks"][co] = {"date": datetime.date.today().isoformat(), "head": head,
                                    "hits": sorted(hits.values(), key=lambda h: h["target"])[:100]}
        for h in hits.values():
            a.add(area, h["severity"], "committed-secret", h["target"], h["title"], h["detail"],
                  "Rotate the secret first (it is in history even if the file was changed), then remove it from "
                  "the code. In a test file it is usually a made-up value: check, then accept the finding or add a "
                  "`.gitleaksignore` entry.")


# ---------------------------------------------------------------------------- area: supply chain

LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
             "requirements.txt", "poetry.lock", "Pipfile.lock", "uv.lock", "Gemfile.lock", "composer.lock", "go.sum",
             "Cargo.lock", "Package.resolved"]


def check_supply(a, checkouts):
    area = "supply"
    osv = have("osv-scanner")
    if not osv:
        a.note(area, "osv-scanner is not installed: only npm lockfiles were audited (with npm audit), and known "
                     "malicious packages were checked by file indicators only (`brew install osv-scanner`).")
    install_scripts = set()
    for co in checkouts:
        short = co.replace(HOME, "~")
        locks = []
        for dirpath, dirnames, filenames in os.walk(co):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            if dirpath.count(os.sep) - co.count(os.sep) > 3:
                dirnames[:] = []
            locks += [os.path.join(dirpath, f) for f in filenames if f in LOCKFILES]
        if not locks:
            continue
        a.count(area, "projects with lockfiles")
        # 1. indicators of known npm worms, in the tree and in installed node_modules
        rc, out, _ = run(["find", co, "-name", ".git", "-prune", "-o", "(", "-name", "setup_bun.js", "-o", "-name",
                          "bun_environment.js", "-o", "-name", "shai-hulud*", "-o", "-name", "truffleSecrets.json",
                          ")", "-print"], timeout=180)
        for f in out.splitlines()[:10]:
            a.add(area, "critical", "worm-ioc", f.replace(HOME, "~"), "File from a known npm worm found",
                  "%s is a Shai-Hulud indicator." % f.replace(HOME, "~"),
                  "Treat the machine as compromised: disconnect, rotate npm/GitHub/cloud tokens and SSH keys, "
                  "delete node_modules and reinstall from a clean lockfile, and check GitHub for new repos and "
                  "workflows created by your account.")
        for wf in glob.glob(os.path.join(co, ".github/workflows/*")):
            if os.path.basename(wf) in {"discussion.yaml", "discussion.yml", "shai-hulud-workflow.yml"}:
                text = read_text(wf) or ""
                if "self-hosted" in text or "discussion" in text:
                    a.add(area, "critical", "worm-workflow", wf.replace(HOME, "~"), "Backdoor workflow from an npm worm",
                          wf.replace(HOME, "~"), "Delete the workflow, remove self-hosted runners you did not add, "
                                                 "and rotate secrets.")
        # 2. npm lockfile details
        for lock in locks:
            if os.path.basename(lock) not in ("package-lock.json", "npm-shrinkwrap.json"):
                continue
            data = load_json(lock, {})
            odd = []
            for path, pkg in (data.get("packages") or {}).items():
                if not path:
                    continue
                name = path.split("node_modules/")[-1]
                res = pkg.get("resolved") or ""
                if res and not res.startswith("https://registry.npmjs.org/") and not pkg.get("link"):
                    odd.append("%s -> %s" % (name, res[:90]))
                if pkg.get("hasInstallScript"):
                    install_scripts.add("%s|%s@%s" % (lock.replace(HOME, "~"), name, pkg.get("version")))
            if odd:
                a.add(area, "medium", "non-registry", lock.replace(HOME, "~"),
                      "%d dependencies come from outside the npm registry" % len(odd), "; ".join(odd[:5]),
                      "Git and URL dependencies skip registry malware scanning and can change under you. Pin them "
                      "to a commit or publish them to a registry.")
            if not osv and have("npm") and os.path.isfile(os.path.join(os.path.dirname(lock), "package.json")):
                rc, out, _ = run(["npm", "audit", "--json", "--package-lock-only", "--omit=dev"],
                                 timeout=180, cwd=os.path.dirname(lock))
                try:
                    vul = json.loads(out).get("metadata", {}).get("vulnerabilities", {})
                except ValueError:
                    vul = {}
                crit, high = vul.get("critical", 0), vul.get("high", 0)
                if crit or high:
                    a.add(area, "high" if crit else "medium", "npm-audit", lock.replace(HOME, "~"),
                          "%d critical / %d high vulnerable npm dependencies" % (crit, high),
                          "Production dependencies in %s." % os.path.dirname(lock).replace(HOME, "~"),
                          "Run `npm audit fix` (or update the named packages) and test.")
        # 3. osv-scanner over every lockfile
        if osv:
            rc, out, _ = run(["osv-scanner", "scan", "source", "-r", "--format", "json", co], timeout=600)
            try:
                results = json.loads(out).get("results", [])
            except ValueError:
                results = []
            vulns, mal = 0, []
            for r in results:
                for p in r.get("packages", []):
                    for v in p.get("vulnerabilities", []):
                        if v.get("id", "").startswith("MAL-"):
                            mal.append("%s@%s (%s)" % (p["package"]["name"], p["package"].get("version"), v["id"]))
                        else:
                            vulns += 1
            if mal:
                a.add(area, "critical", "malicious-package", short, "Known malicious package in a lockfile",
                      "; ".join(mal[:5]), "Remove it, delete node_modules, rotate any tokens on machines that "
                                          "installed it.")
            if vulns:
                a.add(area, "medium", "osv", short, "%d known vulnerabilities in dependencies" % vulns, short,
                      "Run `osv-scanner scan source -r %s` for the list and update the packages." % short)
    a.count(area, "npm packages with install scripts", len(install_scripts))
    new = a.diff_baseline("supply.install-scripts", install_scripts)
    if new:
        a.add(area, "medium", "new-install-scripts", "lockfiles",
              "%d newly added npm packages run code at install time" % len(new),
              "; ".join(n.split("|")[1] + " in " + n.split("|")[0] for n in new[:8]),
              "Check each on socket.dev or npm before the next `npm install`; install scripts are how malicious "
              "packages execute.")


# ---------------------------------------------------------------------------- area: github

def gh(path, raw=False, paginate=False, timeout=60):
    """Return (status, data). status is 200 on success, else the HTTP code (or 0 for other failures)."""
    cmd = ["gh", "api", path]
    if raw:
        cmd[2:2] = ["-H", "Accept: application/vnd.github.raw"]
    if paginate:
        cmd += ["--paginate", "--jq", ".[]"]
    rc, out, err = run(cmd, timeout=timeout)
    if rc != 0:
        m = re.search(r"HTTP (\d{3})", err)
        return (int(m.group(1)) if m else 0), None
    if raw:
        return 200, out
    if paginate:
        return 200, [json.loads(l) for l in out.splitlines() if l.strip()]
    if not out.strip():
        return 204, None
    try:
        return 200, json.loads(out)
    except ValueError:
        return 0, None


ACTION_REF = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^@\s'\"]+)@([^\s'\"#]+)", re.M)
UNTRUSTED_CTX = re.compile(
    r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|"
    r"workflow_run|pages)[\w.\[\]*]*\.(title|body|message|name|email|head_branch|ref|label|default_branch)|"
    r"github\.head_ref)\s*\}\}")


def analyze_workflow(a, repo, path, text):
    area = "github"
    target = "%s/%s" % (repo, path)
    name = os.path.basename(path)
    if name in {"discussion.yaml", "discussion.yml", "shai-hulud-workflow.yml"} or "SHA1HULUD" in text:
        a.add(area, "critical", "worm-workflow", target, "Workflow matches the Shai-Hulud backdoor", target,
              "Delete it, remove unknown self-hosted runners, rotate the repository's secrets.")
    code = "\n".join(re.sub(r"(^|\s)#.*$", "", l) for l in text.splitlines())
    triggers_prt = re.search(r"^\s*pull_request_target\s*:|on:.*pull_request_target|- pull_request_target",
                             code, re.M)
    checks_out_head = re.search(r"\bref:\s*['\"]?(\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|"
                                r"github\.head_ref)|refs/pull/)", code)
    if triggers_prt and checks_out_head:
        a.add(area, "high", "prt-checkout", target,
              "pull_request_target workflow checks out the pull request's code",
              "Code from a pull request runs with the repository's secrets and write token ('pwn request').",
              "Use `pull_request` for anything that runs PR code, or keep the privileged job from executing the "
              "checked-out files.")
    # script injection: untrusted context inside a run: block
    in_run, run_indent = False, 0
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if re.match(r"-?\s*run:\s*", stripped):
            in_run, run_indent = True, indent
            body = stripped.split("run:", 1)[1]
        elif in_run and stripped and indent <= run_indent:
            in_run = False
            body = ""
        else:
            body = line if in_run else ""
        if body and UNTRUSTED_CTX.search(body):
            a.add(area, "high", "script-injection", "%s:%d" % (target, i),
                  "Workflow puts attacker-controlled text straight into a shell command",
                  "%s line %d: %s" % (target, i, stripped[:140]),
                  "Pass it through an environment variable (`env: TITLE: ${{ ... }}` then `\"$TITLE\"`).")
            break
    unpinned = []
    for owner_repo, ref in ACTION_REF.findall(text):
        if owner_repo.startswith("./") or owner_repo.startswith("docker://"):
            continue
        owner = owner_repo.split("/")[0].lower()
        if owner in FIRST_PARTY_ACTION_OWNERS:
            continue
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            unpinned.append("%s@%s" % (owner_repo, ref))
    if unpinned:
        a.add(area, "medium", "unpinned-action", target,
              "Third-party action pinned to a movable tag",
              "%s: %s" % (target, ", ".join(sorted(set(unpinned))[:6])),
              "Pin to a full commit SHA (`pinact run` or `ratchet pin`); a retagged action ran malicious code in "
              "the tj-actions/changed-files compromise.")
    if not re.search(r"^permissions\s*:", text, re.M):
        a.add(area, "low", "no-permissions", target, "Workflow does not limit its GITHUB_TOKEN permissions", target,
              "Add `permissions: contents: read` at the top and grant more per job only where needed.")


def audit_repo(a, repo, info):
    area = "github"
    name = repo["full_name"]
    default = repo.get("default_branch") or "main"
    private = repo.get("private")
    st, full = gh("repos/%s" % name)
    sa = (full or repo).get("security_and_analysis") or {}
    out = {"public": not private}
    st, _ = gh("repos/%s/vulnerability-alerts" % name)
    if st in (200, 204):
        st, alerts = gh("repos/%s/dependabot/alerts?state=open&per_page=100" % name, paginate=True)
        alerts = alerts or []
        sev = {}
        for al in alerts:
            s = (al.get("security_advisory") or {}).get("severity", "unknown")
            sev[s] = sev.get(s, 0) + 1
        crit, high = sev.get("critical", 0), sev.get("high", 0)
        if crit or high:
            pk = sorted({"%s (%s)" % ((al.get("dependency") or {}).get("package", {}).get("name"),
                                      al["security_advisory"]["severity"]) for al in alerts
                         if al["security_advisory"]["severity"] in ("critical", "high")})
            a.add(area, "high" if crit else "medium", "dependabot-open", name,
                  "%d critical / %d high open Dependabot alerts" % (crit, high), ", ".join(pk[:8]),
                  "Merge the Dependabot pull requests or update the packages: https://github.com/%s/security/"
                  "dependabot" % name)
        elif alerts:
            a.add(area, "low", "dependabot-open", name, "%d open moderate/low Dependabot alerts" % len(alerts), "",
                  "https://github.com/%s/security/dependabot" % name)
    elif st == 404:
        a.add(area, "medium", "dependabot-off", name, "Dependabot alerts are turned off",
              "GitHub will not tell you when a dependency has a known vulnerability or is malware. Free on private "
              "repositories.",
              "Run `gh api -X PUT repos/%s/vulnerability-alerts` (and `.../automated-security-fixes`), or turn it "
              "on for the whole org in Settings > Code security." % name)
    ss = (sa.get("secret_scanning") or {}).get("status")
    if ss == "enabled":
        st, sal = gh("repos/%s/secret-scanning/alerts?state=open&per_page=100" % name, paginate=True)
        for al in (sal or [])[:10]:
            a.add(area, "high", "secret-alert", "%s#%s" % (name, al.get("number")),
                  "Open secret scanning alert: %s" % al.get("secret_type_display_name"), al.get("html_url", ""),
                  "Rotate the secret, then close the alert.")
    elif not private:
        a.add(area, "high", "secret-scanning-off", name, "Secret scanning is off on a public repository", "",
              "Settings > Code security > Secret Protection: enable secret scanning and push protection (free on "
              "public repos).")
    else:
        info["secret_scanning_off"].append(name)
    st, prot = gh("repos/%s/branches/%s/protection" % (name, default))
    st2, rules = gh("repos/%s/rules/branches/%s" % (name, default))
    protected = st == 200 or (st2 == 200 and rules)
    if not protected:
        if st == 403 or st2 == 403:
            info["protection_unavailable"].append(name)
        else:
            a.add(area, "medium", "unprotected-branch", "%s@%s" % (name, default),
                  "Default branch %s has no protection" % default,
                  "Anyone with write access (or a stolen token) can force-push or push straight to %s." % default,
                  "Add a ruleset: block force pushes and deletion, require a pull request.")
    st, keys = gh("repos/%s/keys" % name)
    if st == 200:
        for k in keys or []:
            info["deploy_keys"].add("%s|%s|%s" % (name, k.get("title"), "rw" if not k.get("read_only") else "ro"))
            if not k.get("read_only"):
                a.add(area, "medium", "deploy-key-write", "%s|%s" % (name, k.get("id")),
                      "Deploy key with write access", "%s: %s (added %s)" % (name, k.get("title"),
                                                                             (k.get("created_at") or "")[:10]),
                      "Make it read-only unless a server must push. A write key on a server can push code.")
    st, collabs = gh("repos/%s/collaborators?affiliation=outside&per_page=100" % name)
    if st == 200:
        for c in collabs or []:
            info["outside"].add("%s|%s" % (name, c.get("login")))
    st, hooks = gh("repos/%s/hooks" % name)
    if st == 200:
        for h in hooks or []:
            info["hooks"].add("%s|%s" % (name, (h.get("config") or {}).get("url", "?")))
    st, runners = gh("repos/%s/actions/runners" % name)
    if st == 200:
        for r in (runners or {}).get("runners", []):
            info["runners"].add("%s|%s" % (name, r.get("name")))
    # workflows
    st, files = gh("repos/%s/contents/.github/workflows?ref=%s" % (name, default))
    if st == 200 and isinstance(files, list):
        for f in files:
            if not f.get("name", "").endswith((".yml", ".yaml")):
                continue
            st, text = gh("repos/%s/contents/%s?ref=%s" % (name, f["path"], default), raw=True)
            if st == 200 and text:
                info["workflows"] += 1
                analyze_workflow(a, name, f["path"], text)
    if have("zizmor") and not a.args.quick:
        rc, zout, _ = run(["zizmor", "--format", "json", "--min-severity", "medium", "--no-progress", name],
                          timeout=300, env=dict(os.environ, GH_TOKEN=info["token"]))
        try:
            zres = json.loads(zout)
        except ValueError:
            zres = []
        for z in zres[:40]:
            if z.get("ident") == "unpinned-uses":  # the audit's own unpinned-action check covers it
                continue
            sev = {"High": "high", "Medium": "medium"}.get((z.get("determinations") or {}).get("severity"), "low")
            loc = ((z.get("locations") or [{}])[0].get("symbolic") or {}).get("key", {})
            where = (loc.get("Remote") or loc.get("Local") or {}).get("path", "") if isinstance(loc, dict) else ""
            if re.search(r"(^|/)(vendor|node_modules)/", where):
                continue
            a.add(area, sev, "zizmor-" + z.get("ident", "x"), "%s/%s" % (name, where),
                  "zizmor: %s" % z.get("desc"), "%s %s" % (name, where), z.get("url", ""))
    return out


def check_github(a):
    area = "github"
    if not have("gh"):
        a.note(area, "GitHub CLI is not installed: GitHub was not checked.")
        return
    rc, out, err = run(["gh", "auth", "status"])
    if rc != 0:
        a.note(area, "gh is not logged in: GitHub was not checked (`gh auth login`).")
        return
    _, me = gh("user")
    login = (me or {}).get("login")
    rc, token, _ = run(["gh", "auth", "token"])
    token = token.strip()
    st, orgs = gh("user/orgs?per_page=100")
    orgs = [o["login"] for o in (orgs or [])]
    a.count(area, "organizations", len(orgs))
    scopes = re.search(r"Token scopes: (.*)", out + err)
    if scopes and "admin:org" not in scopes.group(1):
        a.note(area, "The gh token has no admin:org scope, so org webhooks, org runners and org Actions policy were "
                     "not visible (`gh auth refresh -s admin:org,read:audit_log` adds them).")
    # personal account keys
    st, keys = gh("user/keys")
    if st == 200:
        cur = {"%s|%s" % (k.get("id"), k.get("title")) for k in keys or []}
        a.count(area, "SSH keys on your GitHub account", len(cur))
        for k in a.diff_baseline("github.user-keys", cur) or []:
            a.add(area, "high", "user-key-new", k, "New SSH key on your GitHub account", k.split("|", 1)[1],
                  "Remove it at https://github.com/settings/keys unless you added it.")
    members_all = set()
    for o in orgs:
        st, org = gh("orgs/%s" % o)
        if st != 200:
            continue
        if org.get("two_factor_requirement_enabled") is False:
            a.add(area, "high", "org-2fa", o, "Organization %s does not require two-factor authentication" % o,
                  "A member with a phished password gets your code and secrets.",
                  "https://github.com/organizations/%s/settings/security > Require two-factor authentication." % o)
        if org.get("dependabot_alerts_enabled_for_new_repositories") is False:
            a.add(area, "low", "org-dependabot-default", o, "New repositories in %s start with Dependabot off" % o, "",
                  "Org Settings > Code security > Configurations: apply the GitHub recommended configuration to all "
                  "repositories and set it as the default.")
        if org.get("members_can_create_public_repositories"):
            a.add(area, "low", "org-public-repos", o, "Members of %s can create public repositories" % o,
                  "One wrong click publishes private code.",
                  "Org Settings > Member privileges > Repository creation: untick Public.")
        st, members = gh("orgs/%s/members?per_page=100" % o, paginate=True)
        for m in members or []:
            members_all.add("%s|%s" % (o, m.get("login")))
        st, runners = gh("orgs/%s/actions/runners" % o)
        if st == 200:
            for r in (runners or {}).get("runners", []):
                if "SHA1HULUD" in (r.get("name") or "").upper():
                    a.add(area, "critical", "worm-runner", "%s|%s" % (o, r.get("name")),
                          "Self-hosted runner named like the Shai-Hulud worm", "%s: %s" % (o, r.get("name")),
                          "Remove the runner and treat the machine it runs on as compromised.")
    for m in a.diff_baseline("github.members", members_all) or []:
        a.add(area, "high", "member-new", m, "New member in a GitHub organization", m.replace("|", ": "),
              "Confirm you invited them.")
    # repositories
    st, repos = gh("user/repos?per_page=100&affiliation=owner,organization_member", paginate=True)
    repos = [r for r in (repos or []) if not r.get("archived")]
    a.count(area, "repositories", len(repos))
    for r in repos:
        if r["name"] == "tpcp-docs" or re.search(r"shai.?hulud", r.get("description") or "", re.I):
            a.add(area, "critical", "worm-repo", r["full_name"], "Repository created by a credential-stealing worm",
                  r["full_name"], "Your GitHub token was stolen: revoke tokens, rotate secrets, delete the repo.")
    info = {"secret_scanning_off": [], "protection_unavailable": [], "deploy_keys": set(), "outside": set(),
            "hooks": set(), "runners": set(), "workflows": 0, "token": token}
    publics = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(audit_repo, a, r, info): r for r in repos}
        for f in concurrent.futures.as_completed(futs):
            try:
                if f.result().get("public"):
                    publics.add(futs[f]["full_name"])
            except Exception as e:  # noqa: BLE001
                a.note(area, "Could not audit %s: %s" % (futs[f]["full_name"], e))
    a.count(area, "workflows reviewed", info["workflows"])
    for p in a.diff_baseline("github.public", publics) or []:
        a.add(area, "high", "repo-went-public", p, "Repository became public since the last audit", p,
              "Make it private again if that was not intended, and rotate any secret in its history.")
    for kind, key, title in [("outside", "github.outside", "New outside collaborator"),
                             ("hooks", "github.hooks", "New repository webhook"),
                             ("runners", "github.runners", "New self-hosted runner"),
                             ("deploy_keys", "github.deploy-keys", "New deploy key")]:
        for item in a.diff_baseline(key, info[kind]) or []:
            a.add(area, "high", key.split(".")[1] + "-new", item, title, item.replace("|", ": "),
                  "Confirm it was added on purpose; webhooks, runners and deploy keys are common footholds.")
    if info["secret_scanning_off"]:
        a.add(area, "low", "secret-scanning-off", "private-repos",
              "Secret scanning is off on %d private repositories" % len(info["secret_scanning_off"]),
              "On private repos it needs GitHub Secret Protection ($19 per active committer per month). This audit "
              "runs gitleaks locally instead when it is installed.",
              "Optional: buy Secret Protection for push protection, or keep relying on the local scan.")
    if info["protection_unavailable"]:
        a.note(area, "Branch protection is not available on %d private repos owned by a free account: %s." % (
            len(info["protection_unavailable"]), ", ".join(sorted(info["protection_unavailable"]))))
    a.inventory[area]["login"] = login


# ---------------------------------------------------------------------------- area: servers

def probe_server(host, lynis):
    script = ("PROBE_LYNIS=%d\n" % (1 if lynis else 0)) + (read_text(PROBE) or "")
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes", host,
           "bash -s"]
    rc, out, err = run(cmd, timeout=420 if lynis else 180, input=script)
    facts = {}
    for line in out.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            facts.setdefault(k, []).append(v)
    return rc, facts, err.strip()


def check_servers(a):
    area = "servers"
    hosts = ssh_hosts()
    # one probe per machine, preferring an alias that logs in as root (sees everything)
    by_ip = {}
    for h in hosts:
        try:
            ip = socket.gethostbyname(h["hostname"])
        except OSError:
            ip = h["hostname"]
        cur = by_ip.get(ip)
        if cur is None or (h["user"] == "root" and cur["user"] != "root"):
            by_ip[ip] = dict(h, ip=ip, names=sorted({x["alias"] for x in hosts if x["hostname"] == h["hostname"]}))
    a.count(area, "servers in ssh config", len(by_ip))
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        futs = {ex.submit(probe_server, h["alias"], a.args.lynis): h for h in by_ip.values()}
        results = [(futs[f], f.result()) for f in concurrent.futures.as_completed(futs)]
    for h, (rc, facts, err) in sorted(results, key=lambda x: x[0]["alias"]):
        analyze_server(a, h, rc, facts, err)


def analyze_server(a, h, rc, facts, err):
    area = "servers"
    t = "%s (%s)" % (h["alias"], h["ip"])
    one = lambda k, d="": (facts.get(k) or [d])[0]  # noqa: E731
    if "done" not in facts:
        a.add(area, "medium", "unreachable", h["alias"], "Could not audit server %s" % t,
              (err or "no output")[:300], "Check that the key in ~/.ssh/config still logs in (`ssh %s`)." % h["alias"])
        return
    a.count(area, "servers audited")
    if one("root") != "yes":
        a.note(area, "%s was audited as %s without root: other users' keys, sshd settings and logs were not visible."
               % (t, one("user")))
    prl = one("sshd_permitrootlogin")
    pwa = one("sshd_passwordauthentication")
    if prl == "yes" and pwa == "yes":
        a.add(area, "critical", "root-password-login", t, "Root can log in with a password",
              "PermitRootLogin yes and PasswordAuthentication yes: the server is one guessed password from "
              "being owned.",
              "In /etc/ssh/sshd_config(.d) set `PasswordAuthentication no` and `PermitRootLogin prohibit-password`, "
              "then `systemctl reload ssh` (keep a second session open while testing).")
    elif pwa == "yes":
        a.add(area, "high", "password-login", t, "SSH accepts passwords", "PasswordAuthentication yes",
              "Set `PasswordAuthentication no` once every user has a key.")
    elif prl == "yes":
        a.add(area, "medium", "root-login", t, "Root can log in directly over SSH", "PermitRootLogin yes",
              "Set `PermitRootLogin prohibit-password` (keys only) or `no`.")
    if one("sshd_permitemptypasswords") == "yes":
        a.add(area, "critical", "empty-passwords", t, "SSH accepts empty passwords", "",
              "Set `PermitEmptyPasswords no`.")
    if one("sshd_x11forwarding") == "yes":
        a.add(area, "low", "x11", t, "X11 forwarding is on", "Not needed on a server.", "Set `X11Forwarding no`.")
    # authorized keys
    keys = set()
    for v in facts.get("authkey", []):
        f, fp, rest = (v.split("|", 2) + ["", ""])[:3]
        keys.add("%s %s %s" % (f, fp, rest))
    a.count(area, "authorized keys on servers", len(keys))
    new = a.diff_baseline("servers.authkeys.%s" % h["ip"], keys)
    for k in new or []:
        a.add(area, "high", "authkey-new", "%s|%s" % (h["ip"], k.split()[1]), "New key can log in to %s" % t, k,
              "Confirm who added it (keysync sync, a new laptop?). Remove it from %s if unknown." % k.split()[0])
    for k in a.removed_since("servers.authkeys.%s" % h["ip"], keys):
        a.add(area, "info", "authkey-removed", "%s|%s" % (h["ip"], k.split()[1]), "Key removed from %s" % t, k, "")
    per_file = {}
    for k in keys:
        per_file[k.split()[0]] = per_file.get(k.split()[0], 0) + 1
    for f, n in per_file.items():
        if n >= 8:
            a.add(area, "low", "many-keys", "%s|%s" % (h["ip"], f), "%d keys can log in as %s on %s" % (
                n, f.split("/")[-3] if f.startswith("/home") else "root", t),
                  f, "Remove keys of retired machines and people; each one is a way in. (`keysync` can list "
                     "which accounts own them.)")
    for f in facts.get("nopass_key", []):
        a.add(area, "medium", "server-nopass-key", "%s|%s" % (h["ip"], f), "Passphraseless private key on %s" % t, f,
              "If this is a deploy key, make it read-only on GitHub and scoped to one repository.")
    # firewall and hardening services
    fw_active = one("ufw") == "active" or int(one("nft_input_drop", "0") or 0) > 0
    listen = []
    for v in facts.get("listen", []):
        proto, local, proc = (v.split("|") + ["", ""])[:3]
        addr, _, port = local.rpartition(":")
        if addr.startswith("127.") or addr in ("[::1]",) or addr.endswith("%lo"):
            continue
        listen.append((proto, addr, port, proc))
    exposed = []
    for proto, addr, port, proc in listen:
        if proto != "tcp" or port in WEB_PORTS:
            continue
        try:
            with socket.create_connection((h["ip"], int(port)), timeout=4):
                exposed.append("%s (%s)" % (port, proc))
        except (OSError, ValueError):
            pass
    for e in exposed:
        a.add(area, "high", "exposed-port", "%s|%s" % (h["ip"], e.split()[0]), "Port %s on %s is open to the internet"
              % (e, t), "Reachable from this Mac over the public address.",
              "Bind the service to 127.0.0.1, or block the port with ufw / the Hetzner cloud firewall.")
    if not fw_active and one("root") == "yes":
        a.add(area, "medium" if exposed else "low", "no-firewall", t, "No host firewall on %s" % t,
              "ufw is inactive and nftables has no drop rules; only a cloud firewall (if any) stands in front of "
              "%d listening service(s)." % len(listen),
              "`ufw default deny incoming && ufw allow 22,80,443/tcp && ufw enable` (or keep the Hetzner cloud "
              "firewall and confirm it covers this server).")
    if one("svc_fail2ban") != "active" and one("svc_sshguard") != "active" and one("svc_crowdsec") != "active":
        a.add(area, "low" if pwa != "yes" else "high", "no-fail2ban", t, "No SSH brute-force protection on %s" % t,
              "fail2ban/sshguard/crowdsec are not running.", "`apt install fail2ban`.")
    if one("svc_unattended-upgrades") != "active":
        a.add(area, "medium", "no-auto-updates", t, "Automatic security updates are off on %s" % t, "",
              "`apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades`.")
    sec = int(one("security_upgrades", "0") or 0)
    allup = int(one("upgrades", "0") or 0)
    if sec:
        a.add(area, "medium", "security-updates", t, "%d security updates waiting on %s" % (sec, t), "",
              "`apt update && apt upgrade`.")
    elif allup >= 20:
        a.add(area, "low", "updates", t, "%d package updates waiting on %s" % (allup, t), "", "`apt upgrade`.")
    if "reboot_required" in facts:
        a.add(area, "medium", "reboot", t, "%s needs a reboot to load security patches (up %s days)" % (
            t, one("uptime_days")), "Packages: " + one("reboot_required"),
              "Reboot in a quiet window; until then the patched kernel/libraries are not in use.")
    # accounts and persistence
    uid0 = one("uid0").split()
    if [u for u in uid0 if u != "root"]:
        a.add(area, "critical", "extra-uid0", t, "Account other than root has uid 0 on %s" % t, " ".join(uid0),
              "Classic backdoor. Investigate immediately.")
    pwusers = facts.get("pwuser", [])
    if pwusers:
        a.inventory.setdefault(area, {})["accounts with passwords"] = a.inventory[area].get(
            "accounts with passwords", 0) + len(pwusers)
        if pwa == "yes":
            a.add(area, "medium", "pw-accounts", t, "Accounts with passwords on %s" % t, ", ".join(pwusers),
                  "With password login on, each is guessable. Lock unused ones with `passwd -l`.")
    for k, title in [("cron", "cron"), ("unit", "systemd")]:
        new = a.diff_baseline("servers.%s.%s" % (k, h["ip"]), facts.get(k, []))
        for item in (new or [])[:10]:
            a.add(area, "high", "new-" + k, "%s|%s" % (h["ip"], sha(item)), "New %s job on %s" % (title, t), item[:300],
                  "Confirm you or a deploy added it; new cron jobs and services are how server malware persists.")
    for f in facts.get("unit_changed", []):
        a.add(area, "low", "unit-changed", "%s|%s" % (h["ip"], f), "Service file changed this week on %s" % t, f,
              "Expected after a deploy or package upgrade.")
    for f in facts.get("tmp_exec", []):
        a.add(area, "high", "tmp-exec", "%s|%s" % (h["ip"], f), "Executable file in a temp folder on %s" % t, f,
              "Droppers and miners stage in /tmp and /dev/shm. Check what it is (`file`, `sha256sum`) before "
              "deleting.")
    for m in facts.get("miner", []):
        a.add(area, "critical", "miner", "%s|%s" % (h["ip"], sha(m)), "Process looks like a crypto miner on %s" % t,
              m[:200], "Treat the server as compromised: capture the binary, rebuild the server, rotate its secrets.")
    for p in facts.get("proc", []):
        cpu, user, name = (p.split("|") + ["", ""])[:3]
        try:
            if float(cpu) > 80 or MINER_NAMES.search(name):
                a.add(area, "medium", "cpu", "%s|%s" % (h["ip"], name), "%s uses %s%% CPU on %s" % (name, cpu, t),
                      "user %s" % user, "Check it is your app and not a miner.")
        except ValueError:
            pass
    for f in facts.get("ioc_file", []):
        a.add(area, "critical", "worm-ioc", "%s|%s" % (h["ip"], f), "npm worm file on %s" % t, f,
              "Rotate every credential the server holds and rebuild it from a clean deploy.")
    fl = int(one("failed_logins", "0") or 0)
    a.inventory.setdefault(area, {})["failed SSH logins (7 days)"] = a.inventory[area].get(
        "failed SSH logins (7 days)", 0) + fl
    logins = facts.get("accepted", [])
    srcs = {v.split("|")[0] for v in logins}
    new = a.diff_baseline("servers.login-sources.%s" % h["ip"], srcs)
    for s in (new or [])[:10]:
        a.add(area, "medium", "new-login-source", "%s|%s" % (h["ip"], s), "Login to %s from a new address" % t, s,
              "Expected for a new office/home IP or a CI runner; otherwise investigate.")
    for c in facts.get("container", []):
        name, image, ports = (c.split("|") + ["", ""])[:3]
        if "0.0.0.0:" in ports or ":::" in ports:
            a.add(area, "medium", "container-port", "%s|%s" % (h["ip"], name),
                  "Container %s publishes ports on all interfaces on %s" % (name, t), ports,
                  "Docker bypasses ufw; bind to 127.0.0.1 (`-p 127.0.0.1:PORT:PORT`).")
    for l in facts.get("lynis", []):
        if l.startswith("hardening_index="):
            a.inventory.setdefault(area, {})["Lynis hardening index %s" % h["alias"]] = l.split("=", 1)[1]


# ---------------------------------------------------------------------------- area: claude

RISKY_ALLOW = [
    (r"^Bash$|^Bash\(\*\)$", "high", "any shell command"),
    (r"^Bash\((sudo|su)\b", "high", "commands as root"),
    (r"^Bash\(gh \*\)|^Bash\(gh:\*\)", "medium", "every gh command, including `gh repo delete`, `gh secret set`, "
                                                 "`gh api -X DELETE`"),
    (r"^Bash\(git \*\)|^Bash\(git:\*\)", "medium", "every git command, including `git push --force`"),
    (r"^Bash\((curl|wget)( -\S+)* ?\*\)|^Bash\((curl|wget):\*\)", "medium", "downloads from anywhere"),
    (r"^Bash\(ssh\b[^)]*\*\)", "medium", "any command on that server"),
    (r"^Bash\((npm|npx|pnpm|yarn|bun) \*\)", "medium", "installing and running packages (install scripts run code)"),
    (r"^Bash\((bash|sh|zsh|python3?|node|perl|ruby|eval) ", "medium", "running arbitrary scripts"),
    (r"^Bash\(rm ", "medium", "deleting files"),
    (r"^Bash\([^)]*(deploy|release)[^)]*\)", "low", "deploys without a prompt"),
]


def check_claude(a, checkouts):
    area = "claude"
    cdir = os.path.join(HOME, ".claude")
    if not os.path.isdir(cdir):
        a.note(area, "No ~/.claude folder: Claude checks skipped.")
        return
    settings_files = [os.path.join(cdir, "settings.json"), os.path.join(cdir, "settings.local.json")]
    for co in checkouts:
        settings_files += [os.path.join(co, ".claude", "settings.json"),
                           os.path.join(co, ".claude", "settings.local.json")]
    hooks_seen = set()
    for sf in settings_files:
        s = load_json(sf, None)
        if not isinstance(s, dict):
            continue
        short = sf.replace(HOME, "~")
        perms = s.get("permissions") or {}
        if perms.get("defaultMode") == "bypassPermissions" or s.get("defaultMode") == "bypassPermissions":
            a.add(area, "high", "bypass-mode", short, "Claude runs with all permission prompts bypassed", short,
                  "A prompt injection in any file, web page or tool result can then run anything. Use auto mode "
                  "or explicit allow rules instead.")
        if s.get("enableAllProjectMcpServers"):
            a.add(area, "medium", "all-project-mcp", short, "Every repository's MCP servers start without approval",
                  short, "Remove `enableAllProjectMcpServers`; a cloned repo's .mcp.json can then run code.")
        for rule in perms.get("allow") or []:
            for pat, sev, what in RISKY_ALLOW:
                if re.search(pat, rule):
                    a.add(area, sev, "broad-allow", "%s|%s" % (short, rule),
                          "Allowed without asking: %s" % rule,
                          "In %s. Lets Claude run %s with no prompt, so a prompt injection could too." % (short, what),
                          "Narrow it to the subcommands you need (e.g. `Bash(gh pr view *)`, `Bash(gh pr list *)`).")
                    break
        for event, groups in (s.get("hooks") or {}).items():
            for g in groups or []:
                for hk in g.get("hooks", []):
                    hooks_seen.add("%s|%s|%s" % (short, event, hk.get("command", hk.get("url", ""))[:200]))
    # plugins and marketplaces
    installed = load_json(os.path.join(cdir, "plugins", "installed_plugins.json"), {}).get("plugins", {})
    markets = load_json(os.path.join(cdir, "plugins", "known_marketplaces.json"), {})
    _, orgs = gh("user/orgs?per_page=100") if have("gh") else (0, [])
    _, me = gh("user") if have("gh") else (0, {})
    own = {o["login"].lower() for o in (orgs or [])} | ({(me or {}).get("login", "").lower()} - {""})
    enabled = load_json(os.path.join(cdir, "settings.json"), {}).get("enabledPlugins", {})
    plugin_hashes = {}
    mcp_seen = set()
    for pid, entries in installed.items():
        pname, _, mkt = pid.partition("@")
        src = (markets.get(mkt) or {}).get("source", {})
        repo = src.get("repo") or src.get("url") or src.get("path") or "?"
        a.count(area, "plugins installed")
        if src.get("source") == "github" and repo not in OFFICIAL_MARKETPLACES and repo.split("/")[0].lower() not in own:
            a.add(area, "medium", "third-party-plugin", pid, "Plugin from a third-party marketplace: %s" % pid,
                  "Source %s. Its hooks and commands run with your permissions and update on their own." % repo,
                  "Keep it only if you trust the publisher; pin it or turn off auto-update for that marketplace.")
        elif src.get("source") == "directory":
            a.add(area, "low", "local-plugin", pid, "Plugin installed from a local folder: %s" % pid, repo,
                  "Fine for your own plugins; make sure the folder is not writable by other accounts.")
        for ent in entries:
            path = ent.get("installPath")
            if not path or not os.path.isdir(path):
                continue
            plugin_hashes[pid] = "%s %s" % (ent.get("version"), hash_tree(path))
            for hp in glob.glob(os.path.join(path, "hooks", "hooks.json")) + [os.path.join(path, ".claude-plugin",
                                                                                          "plugin.json")]:
                hj = load_json(hp, {})
                hooks = hj.get("hooks") if isinstance(hj.get("hooks"), dict) else {}
                for event, groups in hooks.items():
                    for g in groups or []:
                        for hk in g.get("hooks", []):
                            hooks_seen.add("%s|%s|%s" % (pid, event, hk.get("command", "")[:200]))
            for mp in [os.path.join(path, ".mcp.json")]:
                for k, v in (load_json(mp, {}).get("mcpServers") or {}).items():
                    mcp_seen.add("%s|%s|%s" % (pid, k, v.get("command", v.get("url", ""))))
            scan_text_tree(a, pid, path, official=repo in OFFICIAL_MARKETPLACES)
    for d in ["skills", "commands", "agents"]:
        p = os.path.join(cdir, d)
        if os.path.isdir(p):
            scan_text_tree(a, "~/.claude/" + d, p, official=False)
    # MCP servers from user and project config
    cj = load_json(os.path.join(HOME, ".claude.json"), {})
    for k, v in (cj.get("mcpServers") or {}).items():
        mcp_seen.add("user|%s|%s %s" % (k, v.get("command", v.get("url", "")), " ".join(v.get("args", []))))
    for proj, pv in (cj.get("projects") or {}).items():
        for k, v in ((pv or {}).get("mcpServers") or {}).items():
            mcp_seen.add("%s|%s|%s %s" % (proj.replace(HOME, "~"), k, v.get("command", v.get("url", "")),
                                          " ".join(v.get("args", []))))
    for co in checkouts:
        for k, v in (load_json(os.path.join(co, ".mcp.json"), {}).get("mcpServers") or {}).items():
            mcp_seen.add("%s/.mcp.json|%s|%s %s" % (co.replace(HOME, "~"), k, v.get("command", v.get("url", "")),
                                                    " ".join(v.get("args", []))))
    for m in mcp_seen:
        if re.search(r"\bnpx\b.*(-y|--yes)\b(?!.*@\d)", m) or re.search(r"\buvx\b(?!.*[=@]\d)", m):
            a.add(area, "medium", "mcp-unpinned", m.split("|")[0] + "|" + m.split("|")[1],
                  "MCP server runs the latest package version on every start", m.replace("|", " · "),
                  "Pin a version (`npx -y pkg@1.2.3`) so a hijacked release cannot run on your machine.")
    a.count(area, "MCP servers configured", len(mcp_seen))
    a.count(area, "hooks registered", len(hooks_seen))
    for hk in a.diff_baseline("claude.hooks", hooks_seen) or []:
        a.add(area, "high", "hook-new", sha(hk), "New Claude hook since the last audit", hk.replace("|", " · "),
              "Hooks run shell commands automatically. Read the command and confirm the plugin or settings change "
              "was yours.")
    for m in a.diff_baseline("claude.mcp", mcp_seen) or []:
        a.add(area, "high", "mcp-new", sha(m), "New MCP server since the last audit", m.replace("|", " · "),
              "Confirm you added it; an MCP server runs code and sees what Claude sees.")
    prev = a.baseline_prev.get("claude.plugin-hashes")
    a.baseline["claude.plugin-hashes"] = plugin_hashes
    if isinstance(prev, dict):
        for pid, v in plugin_hashes.items():
            if pid in prev and prev[pid] != v:
                a.add(area, "info", "plugin-changed", pid, "Plugin updated since the last audit: %s" % pid,
                      "%s -> %s" % (prev[pid].split()[0], v.split()[0]),
                      "Third-party updates deserve a skim of the changelog; the content checks above ran on the new "
                      "version.")
            elif pid not in prev:
                a.add(area, "medium", "plugin-new", pid, "New plugin installed since the last audit: %s" % pid, v,
                      "Confirm you installed it.")
    tasks = {os.path.basename(p) for p in glob.glob(os.path.join(cdir, "scheduled-tasks", "*"))}
    a.count(area, "scheduled tasks", len(tasks))
    for t in a.diff_baseline("claude.scheduled", tasks) or []:
        a.add(area, "medium", "task-new", t, "New Claude scheduled task: %s" % t,
              os.path.join("~/.claude/scheduled-tasks", t),
              "Scheduled prompts run unattended with your permissions; confirm you created it.")
    for co in checkouts:
        for f in ["CLAUDE.md", "AGENTS.md", ".cursorrules"]:
            text = read_text(os.path.join(co, f))
            if text and HIDDEN_UNICODE.search(text):
                a.add(area, "high", "hidden-unicode", "%s/%s" % (co.replace(HOME, "~"), f),
                      "Hidden characters in an agent instruction file",
                      "%s/%s contains invisible Unicode, a known way to hide prompt injections." % (
                          co.replace(HOME, "~"), f), "Open it with `cat -v` and remove what you did not write.")


def scan_text_tree(a, owner, root, official):
    area = "claude"
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git", "__pycache__", "tests", "test"}]
        for fn in filenames:
            if not fn.endswith((".md", ".json", ".sh", ".py", ".js", ".mjs", ".ts", ".yaml", ".yml", ".txt")):
                continue
            p = os.path.join(dirpath, fn)
            text = read_text(p, 500_000)
            if not text:
                continue
            rel = os.path.relpath(p, root)
            m = HIDDEN_UNICODE.search(text)
            if m:
                a.add(area, "high", "hidden-unicode", "%s|%s" % (owner, rel), "Hidden characters in %s" % owner,
                      "%s contains invisible Unicode U+%04X, a known way to hide instructions from you." % (
                          rel, ord(m.group(0))), "Inspect with `cat -v`. Remove the plugin if you cannot explain it.")
            if official:
                continue
            if fn.endswith(".md") and INJECTION_PHRASES.search(text):
                a.add(area, "low", "injection-phrase", "%s|%s" % (owner, rel),
                      "Instruction-override wording in %s" % owner,
                      "%s: \"%s\"" % (rel, INJECTION_PHRASES.search(text).group(0)),
                      "Usually harmless in security docs; read the surrounding text to be sure.")
            if fn.endswith((".sh", ".py", ".js", ".mjs", ".ts", ".json")):
                e = EXFIL_PATTERNS.search(text)
                if e:
                    a.add(area, "high", "exfil-pattern", "%s|%s" % (owner, rel),
                          "Plugin code downloads-and-runs or touches credentials: %s" % owner,
                          "%s: \"%s\"" % (rel, e.group(0)[:120]),
                          "Read what it does. Remove the plugin if it sends keys or tokens anywhere.")


# ---------------------------------------------------------------------------- report

def finalize(a):
    prev_ids = set(a.prev.get("finding_ids", []))
    today = datetime.date.today().isoformat()
    open_, accepted = [], []
    for f in a.findings:
        f["new"] = (not a.first_run) and f["id"] not in prev_ids
        acc = a.accepted.get(f["id"])
        if acc and (not acc.get("until") or acc["until"] >= today):
            f["accepted"] = acc
            accepted.append(f)
        else:
            open_.append(f)
    key = lambda f: (SEV_ORDER[f["severity"]], f["area"], f["title"])  # noqa: E731
    open_.sort(key=key)
    accepted.sort(key=key)
    resolved = sorted(i for i in prev_ids - {f["id"] for f in a.findings} if i.split(":")[0] in a.args.areas)
    counts = {s: sum(1 for f in open_ if f["severity"] == s) for s in SEV_ORDER}
    return {
        "version": VERSION, "generated": now_iso(), "host": socket.gethostname(), "account": os.environ.get("USER"),
        "first_run": a.first_run, "areas": a.args.areas, "counts": counts,
        "new": sum(1 for f in open_ if f["new"] and f["severity"] in ("critical", "high", "medium")),
        "findings": open_, "accepted": accepted, "resolved": resolved, "fixed": [], "fix_actions": [], "notes": a.notes, "inventory": a.inventory,
        "tools": {t: have(t) for t in ["gitleaks", "betterleaks", "osv-scanner", "zizmor", "lynis"]},
    }


def attach_fixes(rep, actions):
    """Record each fix on its finding; move findings fixed this run out of the open list."""
    by_id = {x["id"]: x for x in actions}
    keep, fixed = [], []
    for f in rep["findings"]:
        x = by_id.get(f["id"])
        if x:
            f["remedy"] = x
        (fixed if x and x["status"] == "fixed" else keep).append(f)
    rep["findings"], rep["fixed"], rep["fix_actions"] = keep, fixed, actions
    rep["counts"] = {s: sum(1 for f in keep if f["severity"] == s) for s in SEV_ORDER}
    rep["new"] = sum(1 for f in keep if f["new"] and f["severity"] in ("critical", "high", "medium"))


REMEDY_LABEL = {"fixed": "Fixed automatically", "pr-opened": "Pull request opened", "pr-open": "Pull request open",
                "declined": "Pull request declined", "skipped": "Not fixed automatically", "failed": "Automatic fix failed", "would-fix": "Would fix",
                "would-open-pr": "Would open a pull request"}


def render_md(rep):
    c = rep["counts"]
    lines = ["# Security audit, %s" % rep["generated"][:10], "",
             "%d critical, %d high, %d medium, %d low open findings; %d new since the last audit; %d resolved." % (
                 c["critical"], c["high"], c["medium"], c["low"], rep["new"], len(rep["resolved"])), ""]
    for f in rep["findings"]:
        if f["severity"] == "info":
            continue
        lines.append("- **%s**%s %s: %s  \n  %s  \n  Fix: %s  \n  `%s`" % (
            f["severity"].upper(), " (NEW)" if f["new"] else "", AREA_TITLES[f["area"]], f["title"],
            f["detail"], f["fix"], f["id"]))
        if f.get("remedy"):
            lines[-1] += "  \n  %s: %s %s" % (REMEDY_LABEL[f["remedy"]["status"]], f["remedy"]["detail"],
                                               f["remedy"]["url"])
    if rep.get("fixed"):
        lines += ["", "## Fixed automatically this run", ""] + [
            "- %s: %s" % (f["target"], f["remedy"]["detail"]) for f in rep["fixed"]]
    if rep["notes"]:
        lines += ["", "## Not checked", ""] + ["- %s" % n["text"] for n in rep["notes"]]
    return "\n".join(lines) + "\n"


def render_html(rep):
    e = html.escape
    c = rep["counts"]
    def card(f):
        tag = '<span class="new">new</span>' if f.get("new") else ""
        acc = ""
        if f.get("accepted"):
            acc = '<p class="acc">Accepted: %s%s</p>' % (e(f["accepted"].get("reason", "")), (
                " (until %s)" % e(f["accepted"]["until"])) if f["accepted"].get("until") else "")
        rem = f.get("remedy")
        if rem:
            link = ' <a href="%s">%s</a>' % (e(rem["url"]), "pull request" if rem["kind"] == "pr" else "settings") \
                if rem["url"].startswith("https://") else ""
            acc += '<p class="rem r-%s"><b>%s:</b> %s%s</p>' % (rem["status"], REMEDY_LABEL[rem["status"]],
                                                              e(rem["detail"]), link)
            if rem["kind"] == "pr" and rem["status"] in ("pr-opened", "pr-open"):
                tag += '<span class="pr">PR</span>'
        return ('<details class="f s-%s"><summary><span class="sev">%s</span>%s<span class="t">%s</span></summary>'
                '<div class="body"><p>%s</p><p class="fix"><b>Fix:</b> %s</p>%s<code>%s</code></div></details>') % (
            f["severity"], f["severity"], tag, e(f["title"]), e(f["detail"]) or "&nbsp;", e(f["fix"]) or "-", acc,
            e(f["id"]))
    tiles = "".join('<div class="tile s-%s"><b>%d</b><span>%s</span></div>' % (s, c[s], s)
                    for s in ["critical", "high", "medium", "low"])
    new = [f for f in rep["findings"] if f.get("new") and f["severity"] != "info"]
    body = []
    if rep["first_run"]:
        body.append('<p class="lead">First audit on this account: everything below is the starting point. From next '
                    'week the page highlights what changed, such as new keys, new startup items, new hooks and new '
                    'collaborators.</p>')
    elif new:
        body.append("<h2>New since the last audit</h2>" + "".join(card(f) for f in new))
    if rep.get("fixed"):
        body.append("<section><h2>Fixed automatically this run <small>%d</small></h2>%s</section>" % (
            len(rep["fixed"]), "".join(card(f) for f in rep["fixed"])))
    for area in AREAS:
        fs = [f for f in rep["findings"] if f["area"] == area]
        if area not in rep["areas"]:
            continue
        inv = rep["inventory"].get(area, {})
        meta = " · ".join("%s %s" % (v, k) if isinstance(v, int) else "%s: %s" % (k, v) for k, v in inv.items())
        body.append('<section><h2>%s <small>%d open</small></h2><p class="meta">%s</p>%s</section>' % (
            e(AREA_TITLES[area]), len([f for f in fs if f["severity"] != "info"]), e(meta),
            "".join(card(f) for f in fs) or '<p class="ok">Nothing found.</p>'))
    if rep["accepted"]:
        body.append("<section><h2>Accepted risks <small>%d</small></h2>%s</section>" % (
            len(rep["accepted"]), "".join(card(f) for f in rep["accepted"])))
    if rep["notes"]:
        body.append("<section><h2>Not checked</h2><ul>%s</ul></section>" % "".join(
            "<li>%s</li>" % e(n["text"]) for n in rep["notes"]))
    tools = ", ".join("%s %s" % (t, "✓" if ok else "missing") for t, ok in rep["tools"].items())
    return """<title>Security audit</title>
<meta name="claude:viewport-fit-sides" content="cover">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@400;500;600&display=swap">
<style>
/* Layout: one reading column; severity tiles, then findings grouped by area, each a collapsible row with a severity stripe */
:root{--bg:#f6f7f8;--card:#ffffff;--fg:#1b1f24;--muted:#5d6670;--line:#dfe3e8;--crit:#b3261e;--high:#c2570c;
--med:#946c00;--low:#2f6aa8;--info:#6f7780;--ok:#2e7d32;--on-crit:#ffffff;
--sans:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
--mono:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121518;--card:#1b1f24;--fg:#e8ebee;
--muted:#99a2ab;--line:#2e343b;--crit:#ff6b60;--high:#ff9a4d;--med:#e3b53c;--low:#6aa8f0;--info:#99a2ab;--ok:#6fcf74;
--on-crit:#121518;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#121518;--card:#1b1f24;--fg:#e8ebee;--muted:#99a2ab;--line:#2e343b;--crit:#ff6b60;
--high:#ff9a4d;--med:#e3b53c;--low:#6aa8f0;--info:#99a2ab;--ok:#6fcf74;--on-crit:#121518;color-scheme:dark}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font:15px/1.55 var(--sans)}
main{max-width:920px;margin:0 auto;padding-block:28px 64px;padding-left:max(16px,env(safe-area-inset-left,0px));
padding-right:max(16px,env(safe-area-inset-right,0px))}
h1{font-size:26px;font-weight:600;margin:0 0 4px;text-wrap:balance}
h2{font-size:17px;font-weight:600;margin:32px 0 6px;text-wrap:balance}h2 small{color:var(--muted);font-weight:400}
.sub,.meta{color:var(--muted);font-size:13px;margin:0 0 8px}
.lead{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;max-width:70ch}
.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin:18px 0}
.tile{background:var(--card);border:1px solid var(--line);border-top:3px solid var(--line);border-radius:8px;
padding:10px 12px}.tile b{display:block;font:500 26px/1.2 var(--mono);font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.tile.s-critical{border-top-color:var(--crit)}.tile.s-high{border-top-color:var(--high)}
.tile.s-medium{border-top-color:var(--med)}.tile.s-low{border-top-color:var(--low)}
.f{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--info);border-radius:6px;margin:6px 0}
.f.s-critical{border-left-color:var(--crit)}.f.s-high{border-left-color:var(--high)}
.f.s-medium{border-left-color:var(--med)}.f.s-low{border-left-color:var(--low)}
.f summary{cursor:pointer;padding:9px 12px;display:flex;gap:10px;align-items:baseline;list-style:none}
.f summary:focus-visible{outline:2px solid var(--low);outline-offset:2px}
.f summary::-webkit-details-marker{display:none}
.sev{font:500 11px/1 var(--mono);text-transform:uppercase;letter-spacing:.06em;min-width:64px;color:var(--info)}
.s-critical .sev{color:var(--crit)}.s-high .sev{color:var(--high)}.s-medium .sev{color:var(--med)}
.s-low .sev{color:var(--low)}.t{flex:1;min-width:0}
.new{font:500 11px/1.6 var(--mono);background:var(--crit);color:var(--on-crit);border-radius:4px;padding:0 6px}
.body{padding:0 12px 10px 86px;min-width:0}.body p{margin:4px 0;overflow-wrap:anywhere;max-width:75ch}
.acc{color:var(--muted)}code{font:12px/1.4 var(--mono);color:var(--muted);overflow-wrap:anywhere}
.ok{color:var(--ok)}ul{padding-left:20px}li{max-width:75ch}
.rem{color:var(--ok)}.rem.r-failed,.rem.r-declined,.rem.r-skipped{color:var(--high)}.rem a{color:inherit}
.pr{font:500 11px/1.6 var(--mono);border:1px solid var(--ok);color:var(--ok);border-radius:4px;padding:0 6px}
@media (max-width:560px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}.body{padding-left:12px}}
</style><main>
<h1>Security audit</h1><p class="sub">%s · %s on %s · %d new · %d resolved since last audit</p>
<div class="tiles">%s</div>%s
<p class="meta" style="margin-top:32px">Scanners: %s. Audit v%s. Accept a risk with
<code>/security-audit accept &lt;id&gt; "reason"</code>.</p></main>""" % (
        e(rep["generated"].replace("T", " ")[:16]), e(rep["account"] or ""), e(rep["host"]), rep["new"],
        len(rep["resolved"]), tiles, "".join(body), e(tools), VERSION)


# ---------------------------------------------------------------------------- main

def cmd_scan(args):
    if os.environ.get("CLAUDE_CODE_REMOTE") == "true":
        print("This audit reads this computer's keys, settings and ssh config; it must run on the Mac itself.")
        return 4
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
    except FileExistsError:
        pid = (read_text(LOCK_FILE) or "0").strip()
        try:
            os.kill(int(pid), 0)
            print("Another audit (pid %s) is running." % pid)
            return 3
        except (OSError, ValueError):
            os.unlink(LOCK_FILE)
            return cmd_scan(args)
    try:
        a = Audit(args)
        checkouts = find_checkouts(checkout_roots()) if set(args.areas) & {"secrets", "supply", "claude"} else []
        a.inventory.setdefault("secrets", {})["local repositories"] = len(checkouts)
        steps = [("mac", lambda: check_mac(a)), ("keys", lambda: check_keys(a)),
                 ("github", lambda: check_github(a)), ("servers", lambda: check_servers(a)),
                 ("secrets", lambda: check_secrets(a, checkouts)), ("supply", lambda: check_supply(a, checkouts)),
                 ("claude", lambda: check_claude(a, checkouts))]
        for area, fn in steps:
            if area not in args.areas:
                continue
            print("· %s" % AREA_TITLES[area], file=sys.stderr, flush=True)
            try:
                fn()
            except Exception as e:  # noqa: BLE001 - one area failing must not hide the others
                a.note(area, "%s check crashed: %s" % (AREA_TITLES[area], e))
        rep = finalize(a)
        if args.fix:
            print("· Safe fixes", file=sys.stderr, flush=True)
            import security_fix
            attach_fixes(rep, security_fix.apply_fixes(rep["findings"], dry_run=args.dry_run))
        # keep baselines of areas that did not run this time
        baseline = dict(a.baseline_prev)
        baseline.update(a.baseline)
        leaks = dict(a.prev.get("leaks-scanned", {}))
        leaks.update(baseline.pop("_leaks", {}))
        prev_ids = a.prev.get("finding_ids", [])
        ran_ids = [f["id"] for f in a.findings]
        kept = [i for i in prev_ids if i.split(":")[0] not in args.areas]
        write_json(STATE_FILE, {"version": VERSION, "last_run": rep["generated"], "baseline": baseline,
                                "finding_ids": sorted(set(ran_ids + kept)), "leaks-scanned": leaks})
        stamp = datetime.datetime.now().strftime("%Y-%m-%d-%H%M")
        os.makedirs(REPORTS_DIR, exist_ok=True)
        write_json(os.path.join(REPORTS_DIR, "%s.json" % stamp), rep)
        for path, text in [(args.html, render_html(rep) if args.html else None),
                           (args.md, render_md(rep) if args.md else None)]:
            if path:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
        if args.json:
            write_json(args.json, rep)
        print_summary(rep)
        return 0
    finally:
        try:
            os.unlink(LOCK_FILE)
        except OSError:
            pass


def print_summary(rep):
    c = rep["counts"]
    print("Security audit %s: %d critical, %d high, %d medium, %d low (%d new, %d resolved, %d accepted)" % (
        rep["generated"][:16], c["critical"], c["high"], c["medium"], c["low"], rep["new"], len(rep["resolved"]),
        len(rep["accepted"])))
    for f in rep["findings"]:
        if f["severity"] in ("critical", "high") or (f["new"] and f["severity"] == "medium"):
            print("  %-8s %s%s — %s" % (f["severity"].upper(), "[NEW] " if f["new"] else "", f["title"],
                                         (f["detail"] or "")[:110]))
            print("           id: %s" % f["id"])
    med = [f for f in rep["findings"] if f["severity"] == "medium" and not f["new"]]
    if med:
        print("  + %d medium findings (see the report)" % len(med))
    acts = rep.get("fix_actions") or []
    if acts:
        by = {}
        for x in acts:
            by[x["status"]] = by.get(x["status"], 0) + 1
        print("Fixes: " + ", ".join("%d %s" % (n, REMEDY_LABEL[s].lower()) for s, n in sorted(by.items())))
        seen = set()
        for x in acts:
            if x["status"] in ("pr-opened", "failed", "declined") and (x["url"] or x["id"]) not in seen:
                seen.add(x["url"] or x["id"])
                print("  %-8s %s %s" % (x["status"], x["detail"][:110], x["url"] or x["id"]))
    for n in rep["notes"]:
        print("Note: %s" % n["text"])


def cmd_accept(args):
    acc = load_json(ACCEPTED_FILE, {})
    until = None
    if args.days:
        until = (datetime.date.today() + datetime.timedelta(days=args.days)).isoformat()
    acc[args.id] = {"reason": args.reason, "until": until, "by": os.environ.get("USER"), "on": now_iso()}
    write_json(ACCEPTED_FILE, acc)
    print("Accepted %s%s: %s" % (args.id, " until %s" % until if until else "", args.reason))
    return 0


def cmd_fix(args):
    reports = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.json")))
    if not reports:
        print("No report yet: run `security_audit.py scan` first.")
        return 2
    rep = load_json(reports[-1], {})
    import security_fix
    acts = security_fix.apply_fixes(rep.get("findings", []), dry_run=args.dry_run)
    print("From the report of %s:" % rep.get("generated", "?")[:16])
    for x in acts:
        print("  %-13s %-50s %s %s" % (x["status"], x["id"][:50], x["detail"][:90], x["url"]))
    if not acts:
        print("  nothing the audit can fix automatically")
    return 0


def cmd_tools(_args):
    for t, why in [("gitleaks", "secrets in git history"), ("osv-scanner", "vulnerable and malicious dependencies"),
                   ("zizmor", "GitHub Actions weaknesses"), ("lynis", "server hardening (install on servers)")]:
        print("%-12s %-8s %s" % (t, "ok" if have(t) else "missing", why))
    missing = [t for t in ["gitleaks", "osv-scanner", "zizmor"] if not have(t)]
    if missing:
        print("Install: brew install %s  (or go install / uv tool install from the official packages)" %
              " ".join(missing))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan")
    s.add_argument("--only", default="", help="comma-separated areas")
    s.add_argument("--skip", default="", help="comma-separated areas")
    s.add_argument("--quick", action="store_true", help="skip slow checks (softwareupdate, zizmor)")
    s.add_argument("--full-history", action="store_true", help="scan all git history for secrets again")
    s.add_argument("--lynis", action="store_true", help="run Lynis on servers that have it installed")
    s.add_argument("--fix", action="store_true", help="then make the safe GitHub fixes and open pull requests")
    s.add_argument("--dry-run", action="store_true", help="with --fix: report the fixes without making them")
    s.add_argument("--html")
    s.add_argument("--json")
    s.add_argument("--md")
    acc = sub.add_parser("accept")
    acc.add_argument("id")
    acc.add_argument("reason")
    acc.add_argument("--days", type=int, default=0)
    fx = sub.add_parser("fix")
    fx.add_argument("--dry-run", action="store_true")
    sub.add_parser("tools")
    args = ap.parse_args(argv)
    if args.cmd == "fix":
        return cmd_fix(args)
    if args.cmd == "accept":
        return cmd_accept(args)
    if args.cmd == "tools":
        return cmd_tools(args)
    if args.cmd != "scan":
        ap.print_help()
        return 2
    only = [x for x in args.only.split(",") if x]
    skip = [x for x in args.skip.split(",") if x]
    bad = [x for x in only + skip if x not in AREAS]
    if bad:
        print("Unknown area(s): %s. Areas: %s" % (", ".join(bad), ", ".join(AREAS)))
        return 2
    args.areas = [x for x in (only or AREAS) if x not in skip]
    return cmd_scan(args)


if __name__ == "__main__":
    sys.exit(main())
