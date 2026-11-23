"""Checks of the Claude Code plugin and of the version, offline.

The plugin is the repository itself: .claude-plugin/ holds the marketplace and the
plugin manifest, skills/ holds one skill that points at README.md. These tests keep
the plugin small (no code that runs by itself) and the version the same everywhere.
"""

import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")

# Plugin parts that run code or change settings without the user asking. The
# plugin root is the repository root, so none of these may appear there
FORBIDDEN = [
    "hooks",
    ".mcp.json",
    ".lsp.json",
    "bin",
    "settings.json",
    "agents",
    "commands",
    "monitors",
    "output-styles",
]


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def readme_version():
    for line in (ROOT / "README.md").read_text(encoding="utf-8").splitlines()[:10]:
        match = re.match(r"^Version: (\d+\.\d+\.\d+)\. ", line)
        if match:
            return match.group(1)
    return None


def key(version):
    return tuple(int(part) for part in version.split("."))


class PluginTest(unittest.TestCase):
    def test_marketplace_lists_the_plugin_at_the_root(self):
        market = load(".claude-plugin/marketplace.json")
        self.assertEqual(market["name"], "vuln-digest")
        self.assertEqual(len(market["plugins"]), 1)
        entry = market["plugins"][0]
        self.assertEqual(entry["name"], "vuln-digest")
        self.assertEqual(entry["source"], "./")
        # The version lives in plugin.json only, so it cannot disagree
        self.assertNotIn("version", entry)

    def test_manifest(self):
        plugin = load(".claude-plugin/plugin.json")
        self.assertEqual(plugin["name"], "vuln-digest")
        self.assertRegex(plugin["version"], SEMVER)
        for field in ("hooks", "mcpServers", "lspServers", "agents", "commands", "settings"):
            self.assertNotIn(field, plugin, f"plugin.json must not declare {field}")

    def test_nothing_runs_by_itself(self):
        for name in FORBIDDEN:
            self.assertFalse((ROOT / name).exists(), f"{name} at the repository root becomes part of the plugin")

    def test_one_skill_that_points_at_the_document(self):
        skills = sorted(p.name for p in (ROOT / "skills").iterdir())
        self.assertEqual(skills, ["vuln-digest"])
        skill_dir = ROOT / "skills" / "vuln-digest"
        self.assertEqual(sorted(p.name for p in skill_dir.iterdir()), ["SKILL.md"])
        text = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        front = re.match(r"^---\n(.*?)\n---\n", text, re.S)
        self.assertIsNotNone(front, "SKILL.md has no frontmatter")
        self.assertIn("name: vuln-digest\n", front.group(1) + "\n")
        self.assertRegex(front.group(1), r"(?m)^description: .{40,}")
        # The skill reads the document, it does not hold a copy of it
        self.assertLess(len(text), 3000)
        for path in ("../../README.md", "../../tools/vuln_feed.py"):
            self.assertIn(path, text)
            self.assertTrue((skill_dir / path).resolve().is_file(), path)

    def test_icon_is_a_square_png(self):
        data = (ROOT / ".claude-plugin" / "icon.png").read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        width = int.from_bytes(data[16:20], "big")
        height = int.from_bytes(data[20:24], "big")
        self.assertEqual(width, height)
        self.assertGreaterEqual(width, 512)
        self.assertLess(len(data), 2_000_000)


class VersionTest(unittest.TestCase):
    def test_checksums_in_version_json(self):
        sums = load("site/version.json")["sha256"]
        for name, path in (("README.md", "README.md"), ("vuln_feed.py", "tools/vuln_feed.py")):
            digest = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
            self.assertEqual(sums[name], digest, f"update sha256 of {name} in site/version.json: sha256sum {path}")

    def test_same_version_everywhere(self):
        plugin = load(".claude-plugin/plugin.json")["version"]
        site = load("site/version.json")
        self.assertEqual(readme_version(), plugin, "README.md Version line and plugin.json differ")
        self.assertEqual(site["version"], plugin, "site/version.json and plugin.json differ")

    def test_releases(self):
        site = load("site/version.json")
        releases = site["releases"]
        self.assertTrue(releases)
        self.assertEqual(releases[0]["version"], site["version"], "the newest release comes first")
        versions = [r["version"] for r in releases]
        for v in versions:
            self.assertRegex(v, SEMVER)
        self.assertEqual(versions, sorted(versions, key=key, reverse=True))
        self.assertEqual(len(versions), len(set(versions)))
        for r in releases:
            self.assertRegex(r["date"], r"^\d{4}-\d{2}-\d{2}$")
            self.assertTrue(10 <= len(r["summary"]) <= 300, r["version"])


if __name__ == "__main__":
    unittest.main()
