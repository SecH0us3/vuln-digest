"""Offline tests for vuln_feed.py. Run from the repository root: python3 -m unittest discover -s tools/tests"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "vuln_feed.py")
FIX = os.path.join(HERE, "fixtures")


def load(path):
    with open(path) as f:
        return json.load(f)


def dump(obj, path):
    with open(path, "w") as f:
        json.dump(obj, f)


class VulnFeedTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.zw = os.path.join(self.dir, "zw.xml")
        self.kev = os.path.join(self.dir, "kev.json")
        shutil.copy(os.path.join(FIX, "zerowire.xml"), self.zw)
        shutil.copy(os.path.join(FIX, "kev.json"), self.kev)
        self.state = os.path.join(self.dir, "state.json")
        self.snap = os.path.join(self.dir, "last_run.json")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_tool(self, *args, ok=True, today="2026-11-20"):
        cmd = [sys.executable, "-I", SCRIPT, *args, "--state", self.state, "--snapshot", self.snap,
               "--zerowire-file", self.zw, "--kev-file", self.kev, "--today", today]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if ok:
            self.assertEqual(p.returncode, 0, p.stderr)
        return p

    def fetch(self, *args, **kw):
        p = self.run_tool("fetch", *args, **kw)
        return json.loads(p.stdout)

    def keys(self, out):
        return {i["key"]: i["status"] for i in out["items"]}

    def edit_feed(self, old, new):
        with open(self.zw) as f:
            s = f.read()
        self.assertIn(old, s)
        with open(self.zw, "w") as f:
            f.write(s.replace(old, new))

    def test_no_state_needs_since(self):
        p = self.run_tool("fetch", ok=False)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("--since", p.stderr)
        self.assertFalse(os.path.exists(self.state))

    def test_bootstrap_since(self):
        out = self.fetch("--since", "2026-11-19")
        # nginx2root has an update dated 11-19, java4shell and old are older, KEV 11-10 is older
        self.assertEqual(self.keys(out), {"zerowire:nginx2root": "updated"})
        self.assertEqual([u["text"] for u in out["items"][0]["new_updates"]],
                         ["F5 says ASLR bypass is needed"])

    def test_no_repeat_after_mark(self):
        out = self.fetch("--since", "2026-01-01")
        self.assertEqual(set(self.keys(out)), {"zerowire:nginx2root", "zerowire:java4shell",
                                               "zerowire:old", "kev:CVE-2026-109618"})
        self.run_tool("mark")
        self.assertFalse(os.path.exists(self.snap))
        self.assertEqual(self.fetch()["items"], [])
        self.assertEqual(load(self.state)["last_digest"], "2026-11-20")

    def test_old_kev_entries_are_not_news(self):
        out = self.fetch("--all")
        self.assertNotIn("kev:CVE-2019-0001", self.keys(out))

    def test_new_update_is_shown_alone(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        self.edit_feed("Initial briefing</li>\n</ul>",
                       'Initial briefing</li>\n<li><time datetime="2026-11-20T09:00:00Z">Nov 20</time>: WAF rules added</li>\n</ul>')
        out = self.fetch()
        self.assertEqual(self.keys(out), {"zerowire:java4shell": "updated"})
        self.assertEqual([u["text"] for u in out["items"][0]["new_updates"]], ["WAF rules added"])

    def test_guid_and_review_date_changes_are_ignored(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        self.edit_feed("java4shell@2026-11-17", "java4shell@2026-11-20")
        self.edit_feed("Last reviewed 2026-11-19", "Last reviewed 2026-11-20")
        self.assertEqual(self.fetch()["items"], [])

    def test_kev_status_change_reopens_item_without_duplicate(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        kev = load(self.kev)
        kev["vulnerabilities"].append({"cveID": "CVE-2026-123007", "vendorProject": "F5", "product": "nginx",
                                       "vulnerabilityName": "nginx RCE", "dateAdded": "2026-11-20",
                                       "shortDescription": "x", "requiredAction": "x", "dueDate": "2026-12-11",
                                       "knownRansomwareCampaignUse": "Unknown", "notes": ""})
        dump(kev, self.kev)
        out = self.fetch()
        self.assertEqual(self.keys(out), {"zerowire:nginx2root": "updated"})
        item = out["items"][0]
        self.assertIn("CVE-2026-123007", item["kev_cves"])
        self.assertIn("added to CISA KEV", item["new_updates"][0]["text"])
        self.run_tool("mark")
        # the briefing leaves the feed: its KEV entry must not come back as news
        self.edit_feed("<guid>nginx2root@2026-11-18</guid>", "<guid>gone@2026-11-18</guid>")
        out = self.fetch()
        self.assertNotIn("kev:CVE-2026-123007", self.keys(out))

    def test_mark_uses_snapshot_not_a_new_fetch(self):
        self.fetch("--since", "2026-01-01")
        # a new update arrives after the digest was written but before mark
        self.edit_feed("Initial briefing</li>\n</ul>",
                       'Initial briefing</li>\n<li><time datetime="2026-11-20T09:00:00Z">Nov 20</time>: late news</li>\n</ul>')
        self.run_tool("mark")
        out = self.fetch()
        self.assertEqual(self.keys(out), {"zerowire:java4shell": "updated"})

    def test_failed_source_does_not_hide_others(self):
        os.remove(self.kev)
        out = self.fetch("--since", "2026-01-01")
        self.assertEqual([e["source"] for e in out["errors"]], ["kev"])
        self.assertIn("zerowire:nginx2root", self.keys(out))

    def test_v2_state_is_migrated(self):
        out = self.fetch("--all")
        nginx = next(i for i in out["items"] if i["key"] == "zerowire:nginx2root")
        v2 = {"version": 2, "last_digest": "2026-11-19",
              "slugs": {"nginx2root": {"first_seen": "2026-11-19", "updates": [u["id"] for u in nginx["updates"]]}}}
        dump(v2, self.state)
        out = self.fetch()
        self.assertNotIn("zerowire:nginx2root", self.keys(out))
        self.assertIn("zerowire:java4shell", self.keys(out))
        self.assertEqual(out["last_digest"], "2026-11-19")

    def test_osv_items(self):
        p = self.run_tool("fetch", "--all", "--sources", "osv", "--osv-file", os.path.join(FIX, "osv.json"))
        out = json.loads(p.stdout)
        item = out["items"][0]
        self.assertEqual(item["key"], "osv:GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(item["fixed_versions"], ["16.4.1"])
        self.assertEqual(item["cves"], ["CVE-2026-126187"])


if __name__ == "__main__":
    unittest.main()
