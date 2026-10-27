# security-audit

A Claude Code plugin that runs a weekly security audit across everything one Mac account can reach: the
Mac itself, its SSH keys, the local git checkouts, every GitHub org and repository the `gh` login can see, every
server in `~/.ssh/config`, and Claude Code's own plugins, hooks, MCP servers and permissions. It reports each
finding with a severity and the fix, makes the GitHub fixes that cannot break a repository, and opens pull requests
for the code changes. From the second run on, it also reports what changed since last week: new keys
on a server, new startup items, new hooks, new collaborators, new packages with install scripts.

Private plugin for David Shor's organizations, beside the other `shorconsulting` plugins.

## Install (each account)

```
/plugin marketplace add shorconsulting/security-audit
/plugin install security-audit@security-audit
```

Then `/security-audit schedule` to create two local scheduled tasks: the audit every Friday at 05:00 US Central, so
the report is ready before the weekend, and a re-check every Wednesday at 05:00 that lists what is still open.

It needs `python3` (3.9+), `git`, `ssh` and `gh` (logged in). Each of these scanners is optional, and the audit
uses it when it is installed:

```bash
brew install gitleaks osv-scanner zizmor
```

| Tool | Adds |
| --- | --- |
| gitleaks (or betterleaks) | secrets in git history |
| osv-scanner | vulnerable and **known-malicious** packages across npm, PyPI, Go, Cargo, Swift, Composer and more |
| zizmor | deeper GitHub Actions analysis |
| lynis (on servers, run with `--lynis`) | a hardening score for each server |

## Commands

| Command | What it does |
| --- | --- |
| `/security-audit` | Runs the audit, publishes the `Security audit` page and summarizes critical and new findings |
| `/security-audit schedule` | Creates the Friday audit and the Wednesday re-check as local scheduled tasks (05:00 Central) |
| `/security-audit accept <id> "reason" [--days 90]` | Moves a finding you accept (for example a bot's key that has no passphrase) to "Accepted risks" |
| `/security-audit fix-group <id>` | Guided fix of one group: shows what it touches, checks connectivity before, makes the change with your OK, checks again and rolls back on a regression |
| `/security-audit groups` | Lists the fix groups of the latest report |
| `/security-audit recheck` | Mid-week reminder: re-runs the audit and lists what is still open since the weekly audit |
| `/security-audit fix --dry-run` | Shows the safe fixes the next run would make, without making them |
| `... --no-fix` | Audits only, with no fixes or pull requests |
| `/security-audit tools` | Shows which optional scanners are installed |
| `... --only github,servers` / `--skip supply` | Limits the audit to some areas |
| `... --quick` | Skips the slow checks (`softwareupdate`, zizmor) |

The script also runs on its own: `python3 scripts/security_audit.py scan --html report.html`.

## Fix groups

A Fix plan table at the top lists every group with where it is (repositories, servers and the projects on them, production marked) and its production impact: no production impact, production without downtime, deploys to production on merge, or needs downtime.

The page bundles findings into fix groups: one change in one place, checked by one set of tests, such as all
committed secrets in one repository or all SSH settings on one server. Each group says what the change touches,
from that run's data: which logins use a key, who logged in to a server this week and by which method, which
services listen. It also lists the steps, the connectivity checks run before and after (ssh to every alias, failed
services, open ports, HTTP, CI on the default branch), and the rollback.

The Fix button copies `/security-audit fix-group <id>`. The page cannot run anything on your Mac, so paste the
command into Claude Code. It snapshots the checks, makes the change with your OK at each risky step, compares the
checks, and rolls back if something that worked before fails. Outcomes go to `~/.security-audit/fixes.json` and show
on the page.

## What it fixes on its own

Only changes that cannot break a working repository (`scripts/security_fix.py`):

| Finding | Fix | How |
| --- | --- | --- |
| Dependabot alerts off | Alerts and security-update pull requests on | setting |
| Secret scanning off on a public repo | Secret scanning and push protection on | setting |
| Default branch unprotected | Ruleset blocking deletion and force pushes of `main`/`master`/`develop` (skipped if a workflow force-pushes) | setting |
| Third-party action on a movable tag | Pinned to the commit the tag points to now, plus `.github/dependabot.yml` for actions | pull request, never merged by the plugin |

A pull request you close without merging is not opened again. Everything else (keys, servers, org 2FA, workflow token
permissions, `pull_request_target` workflows) stays on the report for you to decide.

## What it never does

The scan never changes a setting, key, server or repository; the fixes above are the only changes, and only on GitHub. On servers it pipes `scripts/server_probe.sh`, a script that
only reads, over ssh. It uses `sudo -n` when the account has passwordless sudo, and does not prompt for a password.
GitHub is read through `gh api` with your existing token. Findings quote only file names, fingerprints and rule
names, never secret values (gitleaks runs with `--redact`).

## What it does not cover, and what to pair it with

- **Bugs in your own code** (injection, auth bypass, IDOR): use Anthropic's
  [`claude-security`](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/claude-security)
  plugin (`/plugin install claude-security@claude-plugins-official`). Run `/claude-security` on each product
  repository about once a month, or on large changes. It also comes from the official marketplace, so it is a safe
  install.
- **Real-time review while Claude writes code**: the
  [`security-guidance`](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance)
  plugin warns about dangerous patterns on each edit and reviews each commit.
- **Malware on the Mac**: this audit looks for persistence and worm indicators, but it is not antivirus. The
  endpoint agent (SentinelOne on this Mac) does that job; the audit flags a Mac that has none.
- **Install-time blocking of malicious npm packages**: Socket (free tier) or `npm config set ignore-scripts true`.
- **Org settings that need `admin:org`**: run `gh auth refresh -s admin:org` to let the audit see org webhooks,
  runners and the Actions policy.
