"""Unit tests for the parts of security_audit.py that decide what is a finding. Run: python3 -m unittest -v"""
import argparse
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import security_audit as sa  # noqa: E402


def audit(prev=None, accepted=None):
    a = sa.Audit(argparse.Namespace(quick=True, full_history=False, lynis=False, areas=sa.AREAS))
    a.prev = prev or {}
    a.baseline_prev = a.prev.get("baseline", {})
    a.first_run = not a.prev
    a.accepted = accepted or {}
    return a


def checks(a):
    return sorted(f["check"] for f in a.findings)


class WorkflowTests(unittest.TestCase):
    def test_pwn_request(self):
        a = audit()
        sa.analyze_workflow(a, "o/r", ".github/workflows/x.yml", """on:
  pull_request_target:
permissions:
  contents: read
jobs:
  t:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""")
        self.assertEqual(checks(a), ["prt-checkout"])

    def test_comment_mentioning_pr_ref_is_not_a_checkout(self):
        a = audit()
        sa.analyze_workflow(a, "o/r", ".github/workflows/x.yml", """# runs on refs/pull/N/merge
on:
  pull_request_target:
permissions: {}
jobs:
  t:
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""")
        self.assertEqual(checks(a), [])

    def test_script_injection_and_unpinned(self):
        a = audit()
        sa.analyze_workflow(a, "o/r", ".github/workflows/x.yml", """on: issues
jobs:
  t:
    steps:
      - uses: tj-actions/changed-files@v45
      - run: |
          echo "${{ github.event.issue.title }}"
""")
        self.assertEqual(checks(a), ["no-permissions", "script-injection", "unpinned-action"])

    def test_env_indirection_is_safe(self):
        a = audit()
        sa.analyze_workflow(a, "o/r", ".github/workflows/x.yml", """on: issues
permissions: {}
jobs:
  t:
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
""")
        self.assertEqual(checks(a), [])

    def test_worm_workflow(self):
        a = audit()
        sa.analyze_workflow(a, "o/r", ".github/workflows/discussion.yaml", "on: discussion\npermissions: {}\n")
        self.assertIn("worm-workflow", checks(a))


class SshConfigTests(unittest.TestCase):
    def test_include_and_identity(self):
        with tempfile.TemporaryDirectory() as d:
            inc = os.path.join(d, "inc")
            with open(inc, "w") as f:
                f.write("Host box\n  HostName 10.0.0.1\n  User root\n  IdentityFile %s/k\n" % d)
            main = os.path.join(d, "config")
            with open(main, "w") as f:
                f.write("Include %s\nHost *\n  ServerAliveInterval 30\nHost github.com\n  User git\n" % inc)
            blocks = sa.parse_ssh_config(main)
        self.assertEqual(blocks[0]["aliases"], ["box"])
        self.assertEqual(blocks[0]["user"], "root")
        self.assertTrue(blocks[0]["identityfiles"][0].endswith("/k"))


class DiffTests(unittest.TestCase):
    def test_baseline_first_sight_then_new(self):
        a = audit()
        self.assertIsNone(a.diff_baseline("k", {"x"}))
        b = audit(prev={"baseline": {"k": ["x"]}, "finding_ids": []})
        self.assertEqual(b.diff_baseline("k", {"x", "y"}), ["y"])

    def test_new_and_accepted(self):
        a = audit(prev={"baseline": {}, "finding_ids": ["keys:no-passphrase:old"]},
                  accepted={"keys:no-passphrase:bot": {"reason": "bot key, restricted", "until": None}})
        a.add("keys", "high", "no-passphrase", "old", "t")
        a.add("keys", "high", "no-passphrase", "new", "t")
        a.add("keys", "high", "no-passphrase", "bot", "t")
        rep = sa.finalize(a)
        self.assertEqual([f["target"] for f in rep["findings"] if f["new"]], ["new"])
        self.assertEqual([f["target"] for f in rep["accepted"]], ["bot"])
        self.assertEqual(rep["counts"]["high"], 2)

    def test_expired_acceptance_reopens(self):
        a = audit(accepted={"keys:x:y": {"reason": "r", "until": "2000-01-01"}})
        a.add("keys", "high", "x", "y", "t")
        self.assertEqual(len(sa.finalize(a)["findings"]), 1)


class GroupTests(unittest.TestCase):
    def test_secrets_group_by_repository(self):
        import security_groups as sg
        a = audit()
        a.add("secrets", "high", "committed-secret", "~/work/x/generic-api-key:a.ts:1", "t",
              "~/work/x at a.ts:1, commit 1 by d")
        a.add("secrets", "high", "committed-secret", "~/work/x/generic-api-key:b.json:1", "t",
              "~/work/x at b.json:1, in 18 commits by d")
        a.add("secrets", "high", "committed-secret", "~/work/y/stripe-access-token:c.ts:9", "t",
              "~/work/y at c.ts:9, commit 2 by d")
        a.add("servers", "critical", "root-password-login", "box (10.0.0.9)", "t")
        a.add("servers", "low", "x11", "box (10.0.0.9)", "t")
        a.add("servers", "medium", "reboot", "box (10.0.0.9)", "t")
        with tempfile.TemporaryDirectory() as d:
            groups = sg.build_groups(sa.finalize(a), numbers_path=os.path.join(d, "n.json"))
        sizes = sorted((g["kind"], len(g["finding_ids"])) for g in groups)
        self.assertEqual(sizes, [("secrets", 1), ("secrets", 2), ("server-patch", 1), ("server-ssh", 2)])
        ssh = next(g for g in groups if g["kind"] == "server-ssh")
        self.assertEqual(ssh["severity"], "critical")
        self.assertTrue(any("PermitRootLogin prohibit-password" in s for s in ssh["steps"]))
        self.assertTrue(ssh["command"].startswith("/security-audit fix-group "))

    def test_numbers_are_permanent(self):
        import security_groups as sg
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "n.json")
            first = [{"id": "a"}, {"id": "b"}]
            sg.assign_numbers(first, path)
            later = [{"id": "c"}, {"id": "b"}]  # a was fixed, c is new
            sg.assign_numbers(later, path)
        self.assertEqual([g["number"] for g in first], [1, 2])
        self.assertEqual({g["id"]: g["number"] for g in later}, {"c": 3, "b": 2})

    def test_compare_flags_only_regressions(self):
        import security_groups as sg
        before = {"results": {"ssh:a": {"ok": True, "value": True, "detail": "ok", "label": "ssh a"},
                              "ssh:b": {"ok": False, "value": False, "detail": "x", "label": "ssh b"},
                              "units:a": {"ok": True, "value": ["logrotate.service"], "detail": "", "label": "u"}}}
        after = {"results": {"ssh:a": {"ok": False, "value": False, "detail": "denied", "label": "ssh a"},
                             "ssh:b": {"ok": False, "value": False, "detail": "x", "label": "ssh b"},
                             "units:a": {"ok": True, "value": ["logrotate.service"], "detail": "", "label": "u"}}}
        reg, rec, same = sg.compare(before, after)
        self.assertEqual([r[0] for r in reg], ["ssh a"])
        self.assertEqual(len(same), 2)


class RecheckTests(unittest.TestCase):
    def test_still_open_and_resolved(self):
        base = {"generated": "2026-10-30T05:10", "findings": [
            {"id": "keys:no-passphrase:a", "area": "keys", "severity": "high", "title": "t", "target": "a"},
            {"id": "keys:no-passphrase:b", "area": "keys", "severity": "high", "title": "t", "target": "b"},
            {"id": "servers:reboot:c", "area": "servers", "severity": "medium", "title": "t", "target": "c"},
            {"id": "mac:x:d", "area": "mac", "severity": "low", "title": "t", "target": "d"}]}
        a = audit()
        a.args.areas = ["keys", "mac"]
        a.add("keys", "high", "no-passphrase", "a", "t")
        a.add("keys", "high", "no-passphrase", "new", "t")
        rep = sa.finalize(a)
        sa.mark_recheck(rep, base)
        self.assertEqual(rep["still_open"], ["keys:no-passphrase:a"])
        # b was fixed; the server finding is not judged because servers did not run; low findings are not tracked
        self.assertEqual([r["id"] for r in rep["resolved_since"]], ["keys:no-passphrase:b"])
        self.assertIn("Still open since 2026-10-30", sa.render_html(rep))


class PatternTests(unittest.TestCase):
    def test_hidden_unicode_still_detected(self):
        self.assertTrue(sa.HIDDEN_UNICODE.search("run\u200bthis"))
        self.assertIsNone(sa.HIDDEN_UNICODE.search("plain text"))

    def test_test_paths(self):
        for p in ["apps/api/test/x.test.ts", "src/payments.test.ts", "pkg/__tests__/a.js", "x_test.go"]:
            self.assertTrue(sa.TEST_PATH.search(p), p)
        self.assertIsNone(sa.TEST_PATH.search("apps/api/src/alerts/alerts.controller.ts"))


class FixTests(unittest.TestCase):
    def test_pin_text_pins_third_party_only(self):
        import security_fix as sf
        sha_ = "a" * 40
        text = ("steps:\n"
                "  - uses: actions/checkout@v4\n"
                "  - uses: cloudflare/wrangler-action@v3\n"
                "    with: {x: 1}\n"
                "  - uses: 'gradle/actions/setup-gradle@v4'   # build cache\n"
                "  - uses: ./local-action\n"
                "  - uses: tj-actions/changed-files@%s\n" % ("b" * 40))
        seen = []
        new, pinned = sf.pin_text(text, lambda repo, ref: seen.append((repo, ref)) or sha_)
        self.assertEqual(seen, [("cloudflare/wrangler-action", "v3"), ("gradle/actions", "v4")])
        self.assertIn("  - uses: cloudflare/wrangler-action@%s # v3\n" % sha_, new)
        self.assertIn("  - uses: 'gradle/actions/setup-gradle@%s'   # build cache\n" % sha_, new)
        self.assertIn("  - uses: actions/checkout@v4\n", new)
        self.assertEqual(len(pinned), 2)

    def test_unresolved_tag_is_left_alone(self):
        import security_fix as sf
        text = "  - uses: some/action@v1\n"
        self.assertEqual(sf.pin_text(text, lambda r, ref: None), (text, []))

    def test_attach_fixes_moves_fixed_out_of_counts(self):
        a = audit()
        a.add("github", "medium", "dependabot-off", "o/r", "t")
        a.add("github", "medium", "unpinned-action", "o/r/.github/workflows/x.yml", "t")
        rep = sa.finalize(a)
        sa.attach_fixes(rep, [
            {"id": "github:dependabot-off:o/r", "kind": "setting", "status": "fixed", "detail": "d", "url": ""},
            {"id": "github:unpinned-action:o/r/.github/workflows/x.yml", "kind": "pr", "status": "pr-opened",
             "detail": "d", "url": "https://github.com/o/r/pull/1"}])
        self.assertEqual([f["check"] for f in rep["fixed"]], ["dependabot-off"])
        self.assertEqual(rep["counts"]["medium"], 1)
        self.assertEqual(rep["findings"][0]["remedy"]["status"], "pr-opened")
        self.assertIn("pull/1", sa.render_html(rep))


if __name__ == "__main__":
    unittest.main()
