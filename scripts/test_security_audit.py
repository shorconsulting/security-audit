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


if __name__ == "__main__":
    unittest.main()
