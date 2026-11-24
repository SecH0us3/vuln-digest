"""Offline tests for vuln_feed.py. Run from the repository root: python3 -m unittest discover -s tools/tests"""
import hashlib
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
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


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


class QuickServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        # HTTPServer.server_bind calls socket.getfqdn(), which can take seconds on macOS
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Server:
    """A local HTTP server for feeds and APIs. pages: path -> bytes, or callable"""

    def __init__(self):
        self.pages, self.log, self.headers = {}, [], []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def answer(self, body=None):
                outer.log.append((self.command, self.path))
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                outer.headers.append(hdrs)
                base, _, query = self.path.partition("?")
                page = outer.pages.get(self.path)
                if page is None:
                    page = outer.pages.get(base)
                if callable(page):
                    page = page(body) if self.command == "POST" else page(query, hdrs)
                if page is None:
                    self.send_error(404)
                    return
                if isinstance(page, tuple):
                    self.send_response(page[0])
                    self.send_header("Location", page[1])
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(page if isinstance(page, bytes) else page.encode())

            def do_GET(self):
                self.answer()

            def do_POST(self):
                self.answer(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

            def log_message(self, *args):
                pass

        self.httpd = QuickServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


NODE_RSS = ("<rss><channel><item><title>November 2026 security releases</title>"
            "<link>https://nodejs.org/en/blog/vulnerability/november-2026-security-releases</link>"
            "<pubDate>Wed, 11 Nov 2026 00:00:00 GMT</pubDate>"
            "<description>Fixes CVE-2026-123864 and CVE-2026-123863</description></item></channel></rss>")
DOTNET_ATOM = ('<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>ASP.NET Core security updates</title>'
               '<link rel="self" href="https://example.org/feed/504"/>'
               '<link href="https://github.com/dotnet/announcements/issues/504"/><id>tag:504</id>'
               "<updated>2026-11-10T16:10:00Z</updated><content>CVE-2026-114146</content></entry></feed>")
DEBIAN_RDF = ('<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" '
              'xmlns="http://purl.org/rss/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/">'
              '<channel rdf:about="https://www.debian.org/security/"><title>DSA</title><items><rdf:Seq>'
              '<rdf:li resource="https://www.debian.org/security/2026/dsa-6001"/></rdf:Seq></items></channel>'
              '<item rdf:about="https://www.debian.org/security/2026/dsa-6001"><title>DSA-6001 nginx</title>'
              '<link>https://www.debian.org/security/2026/dsa-6001</link>'
              '<description>CVE-2026-123007</description><dc:date>2026-11-10</dc:date></item>'
              '<item rdf:about="https://www.debian.org/security/2026/dsa-6002"><title>DSA-6002 php</title>'
              '<link>https://www.debian.org/security/2026/dsa-6002</link>'
              '<description>CVE-2026-109618</description><dc:date>2026-11-20</dc:date></item></rdf:RDF>')


def osv_vuln(vid, aliases=(), modified="2026-11-12T00:00:00Z", affected=None):
    return {"id": vid, "summary": f"{vid} summary", "aliases": list(aliases), "published": "2026-11-10T00:00:00Z",
            "modified": modified, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            "affected": affected or []}


def affected(eco, name, fixed):
    return {"package": {"ecosystem": eco, "name": name},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}


NO_PROXY_ENV = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}


class VulnFeedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Server()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def setUp(self):
        self.server.pages.clear()
        self.server.log.clear()
        self.server.headers.clear()
        self.dir = tempfile.mkdtemp()
        self.zw = os.path.join(self.dir, "zw.xml")
        self.kev = os.path.join(self.dir, "kev.json")
        shutil.copy(os.path.join(FIX, "zerowire.xml"), self.zw)
        shutil.copy(os.path.join(FIX, "kev.json"), self.kev)
        self.state = os.path.join(self.dir, "state.json")
        self.snap = os.path.join(self.dir, "last_run.json")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def feeds_file(self, **feeds):
        """Serve each feed and write a feeds file that lists them"""
        path = os.path.join(self.dir, "feeds.txt")
        for name, body in feeds.items():
            self.server.pages[f"/{name}.xml"] = body
        write(path, "".join(f"{n}|{self.server.url}/{n}.xml\n" for n in feeds))
        return path

    def run_tool(self, *args, ok=True, today="2026-11-20", env=None):
        cmd = [sys.executable, "-I", SCRIPT, *args, "--state", self.state, "--snapshot", self.snap,
               "--zerowire-file", self.zw, "--kev-file", self.kev, "--today", today]
        run_env = {**NO_PROXY_ENV, **(env or {})}
        p = subprocess.run(cmd, capture_output=True, text=True, env=run_env)
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
        # the user never saw nginx2root: it is new to them, with only the update inside the window
        self.assertEqual(self.keys(out), {"zerowire:nginx2root": "new"})
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
        # fingerprints exactly as the prototype computed them: sha1("<datetime attribute>|<text>")
        def v2(stamp, text):
            return hashlib.sha1(f"{stamp}|{text}".encode()).hexdigest()[:16]
        v2 = {"version": 2, "last_digest": "2026-11-19",
              "slugs": {"nginx2root": {"first_seen": "2026-11-19", "updates": [
                  v2("2026-11-18T10:00:00Z", "Initial briefing"),
                  v2("2026-11-19T08:00:00Z", "F5 says ASLR bypass is needed")]},
                        "old": {"first_seen": "2026-11-19", "updates": [
                  hashlib.sha1(b"old@2026-10-01").hexdigest()[:16]]}}}
        dump(v2, self.state)
        out = self.fetch()
        self.assertNotIn("zerowire:nginx2root", self.keys(out))
        self.assertNotIn("zerowire:old", self.keys(out))
        self.assertIn("zerowire:java4shell", self.keys(out))
        self.assertEqual(out["last_digest"], "2026-11-19")

    def test_history_lists_delivered_items_only(self):
        self.fetch("--since", "2026-11-19")  # java4shell is older than --since: seen, not delivered
        self.run_tool("mark")
        rows = json.loads(self.run_tool("history", "--days", "7").stdout)
        self.assertEqual([r["key"] for r in rows], ["zerowire:nginx2root"])
        self.assertEqual(rows[0]["last_shown"], "2026-11-20")
        self.assertEqual(rows[0]["last_update"], "F5 says ASLR bypass is needed")
        self.assertIn("CVE-2026-123007", rows[0]["cves"])
        later = json.loads(self.run_tool("history", "--days", "7", today="2026-12-20").stdout)
        self.assertEqual(later, [])

    def test_truncated_feed_keeps_complete_items(self):
        with open(self.zw) as f:
            s = f.read()
        cut = s.index("<title>Old item")  # the feed ends in the middle of the third item
        with open(self.zw, "w") as f:
            f.write(s[:cut + 20])
        out = self.fetch("--all")
        self.assertEqual(set(self.keys(out)) - {"kev:CVE-2026-109618"},
                         {"zerowire:nginx2root", "zerowire:java4shell"})
        partial = [e for e in out["errors"] if e["source"] == "zerowire"]
        self.assertEqual(len(partial), 1)
        self.assertTrue(partial[0]["partial"])

    def test_vendor_feeds_rss_and_atom(self):
        feeds = self.feeds_file(node=NODE_RSS, dotnet=DOTNET_ATOM)
        with open(feeds, "a") as f:
            f.write(f"# comment\nbroken|{self.server.url}/nonexistent.xml\n")
        out = self.fetch("--since", "2026-11-11", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual(self.keys(out), {
            "feed:node:https://nodejs.org/en/blog/vulnerability/november-2026-security-releases": "new"})
        self.assertEqual(out["items"][0]["cves"], ["CVE-2026-123863", "CVE-2026-123864"])
        self.assertEqual([e["source"] for e in out["errors"]], ["feeds:broken"])
        allout = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        dotnet = next(i for i in allout["items"] if i["source"] == "feeds:dotnet")
        self.assertEqual((dotnet["date"], dotnet["link"]), ("2026-11-10", "https://github.com/dotnet/announcements/issues/504"))

    def test_feed_url_must_be_http(self):
        feeds = os.path.join(self.dir, "feeds.txt")
        with open(feeds, "w") as f:
            f.write("odd|ftp://example.com/feed.xml\n")
        out = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual(out["items"], [])
        self.assertEqual([e["source"] for e in out["errors"]], ["feeds:odd"])
        self.assertIn("not an http(s) URL", out["errors"][0]["error"])
        # non-http(s) <link> inside a feed entry is stripped
        self.server.pages["/js.xml"] = "<rss><channel><item><title>JS</title><link>javascript:alert(1)</link><guid>g1</guid></item></channel></rss>"
        write(feeds, f"js|{self.server.url}/js.xml\n")
        out_js = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual(out_js["items"][0]["link"], "")

    def test_osv_items(self):
        p = self.run_tool("fetch", "--all", "--sources", "osv", "--osv-file", os.path.join(FIX, "osv.json"))
        out = json.loads(p.stdout)
        item = out["items"][0]
        self.assertEqual(item["key"], "osv:GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(item["fixed_versions"], ["16.4.1"])
        self.assertEqual(item["cves"], ["CVE-2026-126187"])


    # ---------- new sources and the first run ----------

    def test_new_feed_does_not_flood(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        # a month later the user adds a vendor feed: its archive is not news, today's entry is
        feeds = self.feeds_file(debian=DEBIAN_RDF)
        out = self.fetch("--sources", "zerowire,kev,feeds", "--feeds", feeds, today="2026-11-21")
        self.assertEqual(self.keys(out), {"feed:debian:https://www.debian.org/security/2026/dsa-6002": "new"})
        self.assertEqual(load(self.state)["sources"]["feeds:debian"], "2026-11-19")

    def test_source_failed_on_first_run_gets_the_first_cut_off(self):
        os.remove(self.kev)
        self.fetch("--since", "2026-11-01")
        self.run_tool("mark")
        self.assertEqual(load(self.state)["sources"]["kev"], {"pending": "2026-11-01"})
        shutil.copy(os.path.join(FIX, "kev.json"), self.kev)
        out = self.fetch(today="2026-11-21")
        # dated 11-10: after the first run's --since, so it was due on the first run and comes now
        self.assertEqual(self.keys(out), {"kev:CVE-2026-109618": "new"})
        self.assertEqual(load(self.state)["sources"]["kev"], "2026-11-01")

    def test_failed_feed_does_not_flood_later(self):
        feeds = self.feeds_file(debian=DEBIAN_RDF)
        del self.server.pages["/debian.xml"]
        self.fetch("--since", "2026-11-20", "--sources", "feeds", "--feeds", feeds)
        self.run_tool("mark")
        self.server.pages["/debian.xml"] = DEBIAN_RDF
        out = self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-21")
        self.assertEqual(set(self.keys(out)), {"feed:debian:https://www.debian.org/security/2026/dsa-6002"})

    def test_undated_update_is_not_hidden_by_since(self):
        feeds = self.feeds_file(odd="<rss><channel><item><title>No date</title><link>https://x.example/1</link>"
                                    "<pubDate>sometime soon</pubDate></item></channel></rss>")
        out = self.fetch("--since", "2026-11-20", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual(self.keys(out), {"feed:odd:https://x.example/1": "new"})
        self.assertEqual(out["items"][0]["date"], "")

    def test_v3_state_is_migrated(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        st = load(self.state)
        del st["sources"], st["since"]
        st["version"] = 3
        dump(st, self.state)
        self.assertEqual(self.fetch()["items"], [])
        self.run_tool("mark")
        self.assertEqual(load(self.state)["sources"]["zerowire"], "2026-11-20")
        self.assertEqual(load(self.state)["version"], 4)

    # ---------- vendor feeds ----------

    def test_rss1_rdf_feed(self):
        feeds = self.feeds_file(debian=DEBIAN_RDF)
        out = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        got = {i["key"]: (i["date"], i["cves"]) for i in out["items"]}
        self.assertEqual(got, {"feed:debian:https://www.debian.org/security/2026/dsa-6001": ("2026-11-10", ["CVE-2026-123007"]),
                               "feed:debian:https://www.debian.org/security/2026/dsa-6002": ("2026-11-20", ["CVE-2026-109618"])})

    def test_truncated_atom_feed_keeps_complete_entries(self):
        two = DOTNET_ATOM.replace("</feed>", "<entry><title>cut off")
        feeds = self.feeds_file(dotnet=two)
        out = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual([i["link"] for i in out["items"]], ["https://github.com/dotnet/announcements/issues/504"])
        self.assertEqual([(e["source"], e.get("partial")) for e in out["errors"]], [("feeds:dotnet", True)])

    def test_changed_advisory_is_an_update(self):
        feeds = self.feeds_file(node=NODE_RSS)
        self.fetch("--since", "2026-11-01", "--sources", "feeds", "--feeds", feeds)
        self.run_tool("mark")
        self.server.pages["/node.xml"] = NODE_RSS.replace("CVE-2026-123863", "CVE-2026-123863, CVE-2026-123999")
        out = self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-21")
        self.assertEqual(list(self.keys(out).values()), ["updated"])
        self.assertEqual([u["text"] for u in out["items"][0]["new_updates"]], ["advisory changed: adds CVE-2026-123999"])
        self.run_tool("mark", today="2026-11-21")
        self.assertEqual(self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-22")["items"], [])

    def test_hash_in_feed_url_is_not_a_comment(self):
        feeds = self.feeds_file(node=NODE_RSS)
        write(feeds, f"# feeds\nnode|{self.server.url}/node.xml#latest  # Node.js\n")
        out = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual(out["errors"], [])
        self.assertEqual(len(out["items"]), 1)

    def test_check_feeds(self):
        feeds = self.feeds_file(node=NODE_RSS, debian=DEBIAN_RDF, blog="<!DOCTYPE html><html><body>Blog</body></html>",
                                news="<rss><channel><item><title>We raised a round</title>"
                                     "<pubDate>Wed, 11 Nov 2026 00:00:00 GMT</pubDate></item></channel></rss>")
        with open(feeds, "a") as f:
            f.write(f"gone|{self.server.url}/gone.xml\n")
        rows = {r["name"]: r for r in json.loads(self.run_tool("check-feeds", "--feeds", feeds).stdout)}
        self.assertTrue(rows["node"]["ok"])
        self.assertEqual((rows["debian"]["format"], rows["debian"]["entries"], rows["debian"]["newest"]),
                         ("RSS 1.0", 2, "2026-11-20"))
        self.assertFalse(rows["blog"]["ok"])
        self.assertIn("HTML page", rows["blog"]["problems"][0])
        self.assertIn("no entry names a CVE", rows["news"]["problems"][0])
        self.assertFalse(rows["news"]["ok"])
        self.assertEqual(rows["debian"]["latest"], ["DSA-6002 php", "DSA-6001 nginx"])
        self.assertIn("404", rows["gone"]["problems"][0])
        self.assertFalse(os.path.exists(self.state))

    def test_cves_in_full_text_and_xhtml(self):
        feeds = self.feeds_file(
            rss='<rss xmlns:content="http://purl.org/rss/1.0/modules/content/"><channel><item><title>Release</title>'
                '<link>https://x.example/r</link><description>Short teaser</description>'
                '<content:encoded><![CDATA[<p>Fixes CVE-2026-1111</p>]]></content:encoded></item></channel></rss>',
            atom='<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Advisory</title><id>a1</id>'
                 '<summary>see below</summary><content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml">'
                 '<p>Fixes <b>CVE-2026-2222</b></p></div></content></entry></feed>',
            notfeed="<sitemap><url>https://x.example/</url></sitemap>")
        out = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual(sorted(c for i in out["items"] for c in i["cves"]), ["CVE-2026-1111", "CVE-2026-2222"])
        self.assertEqual([e["source"] for e in out["errors"]], ["feeds:notfeed"])
        self.assertIn("not an RSS or Atom feed", out["errors"][0]["error"])

    def test_failed_feed_keeps_the_group_cut_off(self):
        feeds = os.path.join(self.dir, "missing.txt")  # the feeds file itself is missing on the first run
        self.fetch("--since", "2026-11-01", "--sources", "feeds", "--feeds", feeds)
        self.run_tool("mark")
        feeds = self.feeds_file(node=NODE_RSS, debian=DEBIAN_RDF)
        del self.server.pages["/debian.xml"]
        self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-25")
        src = load(self.state)["sources"]
        self.assertEqual((src["feeds:node"], src["feeds:debian"]), ("2026-11-01", {"pending": "2026-11-01"}))
        self.assertNotIn("feeds", src)
        self.server.pages["/debian.xml"] = DEBIAN_RDF
        out = self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-26")
        self.assertEqual(len(out["items"]), 3)  # node, and both Debian entries: they are after 2026-11-01

    def test_truncated_prefixed_atom_entries(self):
        feeds = self.feeds_file(a='<atom:feed xmlns:atom="http://www.w3.org/2005/Atom"><atom:entry><atom:title>One</atom:title>'
                                  '<atom:id>1</atom:id></atom:entry><atom:entry><atom:title>cut')
        out = self.fetch("--all", "--sources", "feeds", "--feeds", feeds)
        self.assertEqual([i["title"] for i in out["items"]], ["One"])

    def test_partial_feed_keeps_its_first_cut_off(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        cut = DEBIAN_RDF.replace("</rdf:RDF>", "<item><title>cut")
        feeds = self.feeds_file(debian=cut)
        self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-21")
        self.assertEqual(load(self.state)["sources"]["feeds:debian"], {"pending": "2026-11-19"})
        self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-25")  # no mark: the cut-off stays
        self.assertEqual(load(self.state)["sources"]["feeds:debian"], {"pending": "2026-11-19"})
        self.server.pages["/debian.xml"] = DEBIAN_RDF
        self.fetch("--sources", "feeds", "--feeds", feeds, today="2026-11-26")
        self.assertEqual(load(self.state)["sources"]["feeds:debian"], "2026-11-19")
        self.assertNotIn("feeds", load(self.state)["sources"])

    # ---------- OSV ----------

    def osv_server(self, vulns, batch):
        """vulns: id -> advisory. batch: a list of results for each querybatch call, or one result list"""
        calls = []

        def querybatch(body):
            calls.append(body)
            res = batch(body) if callable(batch) else batch
            return json.dumps({"results": res})
        self.server.pages["/v1/querybatch"] = querybatch
        for vid, v in vulns.items():
            self.server.pages[f"/v1/vulns/{vid}"] = json.dumps(v)
        return calls

    def osv(self, packages, *args, **kw):
        path = os.path.join(self.dir, "packages.txt")
        write(path, packages)
        return self.fetch("--sources", "osv", "--packages", path, "--osv-api", self.server.url + "/v1/", *args, **kw)

    def test_osv_multi_package_advisory(self):
        v = osv_vuln("CVE-2026-1000", affected=[affected("PyPI", "Django", "5.2.9"), affected("PyPI", "django-rest-framework", "3.16.2"),
                                                affected("PyPI", "flask", "9.9"), affected("Debian:12", "python-django", "3:4.2-1")])
        self.osv_server({"CVE-2026-1000": v}, [{"vulns": [{"id": "CVE-2026-1000", "modified": v["modified"]}]},
                                               {"vulns": [{"id": "CVE-2026-1000", "modified": v["modified"]}]}])
        out = self.osv("PyPI|django|5.2.1\nPyPI|Django_REST.framework|3.16.0\n", "--all")
        item = out["items"][0]
        self.assertEqual([p["name"] for p in item["packages"]], ["django", "Django_REST.framework"])
        # PyPI names are normalized; flask and the Debian package are not the user's
        self.assertEqual(item["fixed_versions"], ["3.16.2", "5.2.9"])
        self.assertEqual(item["cves"], ["CVE-2026-1000"])
        self.assertTrue(item["cvss"][0].startswith("CVSS:3.1/"))

    def test_osv_pages_cache_and_failed_advisory(self):
        a = osv_vuln("GHSA-aaaa", ["CVE-2026-2000"], affected=[affected("npm", "next", "16.4.1")])
        b = osv_vuln("GHSA-bbbb", affected=[affected("npm", "next", "16.4.2")])

        def batch(body):
            q = body["queries"][0]
            if "page_token" not in q:
                return [{"vulns": [{"id": "GHSA-aaaa", "modified": a["modified"]}], "next_page_token": "p2"}]
            return [{"vulns": [{"id": "GHSA-bbbb", "modified": b["modified"]}, {"id": "GHSA-gone", "modified": "x"}]}]
        self.osv_server({"GHSA-aaaa": a, "GHSA-bbbb": b}, batch)
        out = self.osv("npm|next|\n", "--since", "2026-11-01")
        self.assertEqual(set(self.keys(out)), {"osv:GHSA-aaaa", "osv:GHSA-bbbb"})
        self.assertEqual([(e["source"], e.get("partial")) for e in out["errors"]], [("osv", True)])
        self.assertEqual(load(self.state)["sources"]["osv"], "2026-11-01")  # one bad advisory does not keep osv pending
        self.run_tool("mark")
        self.server.log.clear()
        self.assertEqual(self.osv("npm|next|\n", today="2026-11-21")["items"], [])
        gets = [p for m, p in self.server.log if m == "GET"]
        self.assertEqual(gets, ["/v1/vulns/GHSA-gone"])  # the delivered, unchanged advisories are not fetched

    def test_cached_osv_item_comes_back_with_kev_status(self):
        a = osv_vuln("GHSA-aaaa", ["CVE-2026-2000"], affected=[affected("npm", "next", "16.4.1")])
        self.osv_server({"GHSA-aaaa": a}, [{"vulns": [{"id": "GHSA-aaaa", "modified": a["modified"]}]}])
        self.osv("npm|next|16.2.0\n", "--since", "2026-11-01")
        self.run_tool("mark")
        kev = load(self.kev)
        kev["vulnerabilities"].append({"cveID": "CVE-2026-2000", "vendorProject": "Vercel", "product": "Next.js",
                                       "vulnerabilityName": "Next.js RCE", "dateAdded": "2026-11-20", "dueDate": "",
                                       "shortDescription": "", "requiredAction": "", "knownRansomwareCampaignUse": "Known"})
        dump(kev, self.kev)
        path = os.path.join(self.dir, "packages.txt")
        out = self.fetch("--sources", "kev,osv", "--packages", path, "--osv-api", self.server.url + "/v1/", today="2026-11-21")
        self.assertEqual(self.keys(out), {"osv:GHSA-aaaa": "updated"})
        item = out["items"][0]
        self.assertEqual(item["fixed_versions"], ["16.4.1"])
        self.assertEqual(item["kev_cves"]["CVE-2026-2000"]["ransomware"], "Known")

    # ---------- the same CVE from several sources ----------

    def test_same_cve_from_several_sources(self):
        self.fetch("--since", "2026-11-19")  # nginx2root, with CVE-2026-123007, is delivered
        self.run_tool("mark")
        feeds = self.feeds_file(debian=DEBIAN_RDF)
        v = osv_vuln("DEBIAN-CVE-2026-109618", ["CVE-2026-109618"], affected=[affected("Debian", "php8.2", "8.2.36")])
        self.osv_server({v["id"]: v}, [{"vulns": [{"id": v["id"], "modified": v["modified"]}]}])
        out = self.osv("Debian|php8.2|8.2.20\n", "--sources", "feeds,osv", "--feeds", feeds, "--since", "2026-11-01",
                       today="2026-11-21")
        items = {i["key"]: i for i in out["items"]}
        dsa1 = items["feed:debian:https://www.debian.org/security/2026/dsa-6001"]
        self.assertEqual(dsa1["cves_delivered_in"], {"CVE-2026-123007": "zerowire:nginx2root"})
        self.assertEqual(items["osv:DEBIAN-CVE-2026-109618"]["same_cve_items"],
                         ["feed:debian:https://www.debian.org/security/2026/dsa-6002"])

    # ---------- GHSA ----------

    def test_ghsa_repo_and_ecosystem_advisories(self):
        repo_advs = [{
            "ghsa_id": "GHSA-repo-1111-2222",
            "cve_id": "CVE-2026-109618",
            "html_url": "https://github.com/acme/proxy/security/advisories/GHSA-repo-1111-2222",
            "summary": "Request smuggling in proxy",
            "description": "Allows bypassing path rules",
            "severity": "critical",
            "published_at": "2026-11-19T12:00:00Z",
            "updated_at": "2026-11-20T08:00:00Z",
            "cvss_severities": {
                "cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
                "cvss_v4": {"vector_string": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "score": 9.3},
            },
            "vulnerabilities": [{
                "package": {"ecosystem": "go", "name": "github.com/acme/proxy"},
                "vulnerable_version_range": "< 1.31.2",
                "first_patched_version": {"identifier": "1.31.2"},
            }],
        }]
        eco_advs = [{
            "ghsa_id": "GHSA-eco-3333-4444",
            "cve_id": None,
            "identifiers": [{"type": "GHSA", "value": "GHSA-eco-3333-4444"}, {"type": "CVE", "value": "CVE-2026-5555"}],
            "html_url": "https://github.com/advisories/GHSA-eco-3333-4444",
            "summary": "Prototype pollution in widget",
            "description": "Details here",
            "severity": "high",
            "published_at": "2026-11-18T10:00:00Z",
            "updated_at": "2026-11-18T10:00:00Z",
            "cvss": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", "score": 7.5},
            "vulnerabilities": [{
                "package": {"ecosystem": "npm", "name": "widget"},
                "vulnerable_version_range": "<= 2.0.0",
                "first_patched_version": "2.0.1",
            }],
        }]
        seen_auth = []

        def serve_repo(query, hdrs):
            seen_auth.append(hdrs.get("authorization"))
            return json.dumps(repo_advs)

        def serve_eco(query, hdrs):
            self.assertIn("ecosystem=pip", query)  # OSV "PyPI" mapped to GitHub "pip"
            self.assertIn("affects=widget", query)  # one package, not the whole ecosystem
            return json.dumps(eco_advs)

        self.server.pages["/repos/acme/proxy/security-advisories"] = serve_repo
        # Redirect from 127.0.0.1 to localhost (different origin) must strip Authorization
        alt_url = self.server.url.replace("127.0.0.1", "localhost")
        self.server.pages["/repos/acme/redir/security-advisories"] = (302, f"{alt_url}/repos/acme/proxy/security-advisories")
        self.server.pages["/repos/acme/ftp/security-advisories"] = (302, "ftp://example.com/secret")
        self.server.pages["/advisories"] = serve_eco
        ghsa_file = os.path.join(self.dir, "ghsa.txt")
        write(ghsa_file, "# repos and packages\nacme/proxy\nacme/redir\nacme/ftp\npackage|PyPI|widget\nacme/missing\n")
        out = self.fetch("--all", "--sources", "kev,ghsa", "--ghsa", ghsa_file,
                         "--ghsa-api", self.server.url + "/", env={"GITHUB_TOKEN": "example"})
        self.assertEqual(seen_auth, ["Bearer example", None])
        self.assertEqual([e["source"] for e in out["errors"]], ["ghsa:acme/ftp", "ghsa:acme/missing"])
        # Unknown GHSA ecosystem fails fast
        bad_ghsa = os.path.join(self.dir, "bad_ghsa.txt")
        write(bad_ghsa, "package|Debian|openssl\n")
        p = self.run_tool("fetch", "--all", "--sources", "ghsa", "--ghsa", bad_ghsa, ok=False)
        self.assertNotEqual(p.returncode, 0)
        items = {i["key"]: i for i in out["items"]}
        r_item = items["ghsa:GHSA-repo-1111-2222"]
        self.assertEqual(r_item["fixed_versions"], ["1.31.2"])
        self.assertEqual(r_item["cves"], ["CVE-2026-109618"])
        self.assertEqual(r_item["cvss_score"], 9.8)
        self.assertIn("CVE-2026-109618", r_item["kev_cves"])
        e_item = items["ghsa:GHSA-eco-3333-4444"]
        self.assertEqual(e_item["fixed_versions"], ["2.0.1"])
        self.assertEqual(e_item["cves"], ["CVE-2026-5555"])
        self.assertEqual(e_item["cvss_score"], 7.5)

    def test_ghsa_new_repo_does_not_flood_and_tracks_updates(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark")
        advs = [
            {"ghsa_id": "GHSA-old-0001", "cve_id": "CVE-2025-0001", "summary": "Old bug",
             "severity": "high", "published_at": "2026-10-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z",
             "vulnerabilities": []},
            {"ghsa_id": "GHSA-new-0002", "cve_id": None, "summary": "Fresh bug",
             "severity": "high", "published_at": "2026-11-20T00:00:00Z", "updated_at": "2026-11-20T00:00:00Z",
             "vulnerabilities": []},
        ]
        self.server.pages["/repos/acme/app/security-advisories"] = lambda q, h: json.dumps(advs)
        ghsa_file = os.path.join(self.dir, "ghsa.txt")
        write(ghsa_file, "acme/app\n")
        out = self.fetch("--sources", "zerowire,kev,ghsa", "--ghsa", ghsa_file,
                         "--ghsa-api", self.server.url + "/", today="2026-11-21")
        self.assertEqual(self.keys(out), {"ghsa:GHSA-new-0002": "new"})
        self.assertNotIn("ghsa", load(self.state)["sources"])
        self.assertEqual(load(self.state)["sources"]["ghsa:acme/app"], "2026-11-19")
        self.run_tool("mark", today="2026-11-21")
        # later a patch and CVE are added to GHSA-new-0002
        advs[1]["cve_id"] = "CVE-2026-9999"
        advs[1]["updated_at"] = "2026-11-22T09:00:00Z"
        advs[1]["vulnerabilities"] = [{"package": {"ecosystem": "go", "name": "acme/app"},
                                       "first_patched_version": {"identifier": "2.1.0"}}]
        out2 = self.fetch("--sources", "zerowire,kev,ghsa", "--ghsa", ghsa_file,
                          "--ghsa-api", self.server.url + "/", today="2026-11-22")
        self.assertEqual(self.keys(out2), {"ghsa:GHSA-new-0002": "updated"})
        texts = [u["text"] for u in out2["items"][0]["new_updates"]]
        self.assertTrue(any("fixed in 2.1.0" in t for t in texts))

    # ---------- NVD ----------

    def test_nvd_cpe_watch_api_key_and_baseline(self):
        nvd_payload = {
            "totalResults": 3,
            "vulnerabilities": [
                {"cve": {
                    "id": "CVE-2026-7001", "published": "2026-11-18T10:00:00.000",
                    "lastModified": "2026-11-19T12:00:00.000", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "es", "value": "No"}, {"lang": "en", "value": "Auth bypass in FortiOS"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {
                        "baseScore": 9.8, "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                    "configurations": [{"nodes": [{"cpeMatch": [
                        {"vulnerable": True, "criteria": "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
                         "versionStartIncluding": "7.2.0", "versionEndExcluding": "7.2.10"},
                        {"vulnerable": False, "criteria": "cpe:2.3:h:fortinet:fortigate-100f:-:*:*:*:*:*:*:*"},
                    ]}]}],
                }},
                {"cve": {
                    "id": "CVE-2026-7002", "published": "2026-10-01T10:00:00.000",
                    "lastModified": "2026-10-01T10:00:00.000", "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Older bug"}],
                    "metrics": {},
                }},
                {"cve": {
                    "id": "CVE-2026-7003", "published": "2026-11-19T10:00:00.000",
                    "lastModified": "2026-11-19T10:00:00.000", "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "Rejected reason"}],
                    "metrics": {},
                }},
            ],
        }
        seen_queries, seen_keys = [], []

        def serve_nvd(query, hdrs):
            seen_queries.append(query)
            seen_keys.append(hdrs.get("apikey"))
            if "broken" in query:
                return None
            return json.dumps(nvd_payload)

        self.server.pages["/cves"] = serve_nvd
        nvd_file = os.path.join(self.dir, "nvd.txt")
        write(nvd_file, "fortios|cpe:2.3:o:fortinet:fortios\nbroken|cpe:2.3:a:bad:broken\n")
        out = self.fetch("--since", "2026-11-15", "--sources", "nvd", "--nvd", nvd_file,
                         "--nvd-api", self.server.url + "/cves", "--nvd-delay", "0",
                         env={"NVD_API_KEY": "example"})
        self.assertEqual(seen_keys, ["example", "example"])
        # by publication date: old CVEs that NVD modifies again are not news
        self.assertTrue(all("pubStartDate=" in q and "pubEndDate=" in q and "lastMod" not in q for q in seen_queries))
        self.assertEqual([e["source"] for e in out["errors"]], ["nvd:broken"])
        self.assertEqual(self.keys(out), {"nvd:CVE-2026-7001": "new"})
        item = out["items"][0]
        self.assertEqual(item["cvss_score"], 9.8)
        self.assertEqual(item["severity"], "CRITICAL")
        self.assertEqual(item["summary"], "Auth bypass in FortiOS")
        self.assertEqual(item["fixed_versions"], ["7.2.10"])
        self.assertEqual(item["affected"], [">= 7.2.0 < 7.2.10"])
        self.assertNotIn("nvd", load(self.state)["sources"])
        self.assertEqual(load(self.state)["sources"]["nvd:fortios"], "2026-11-15")
        # window > 120 days is clamped to 119 days, and truncated responses flag partial=True
        nvd_payload["totalResults"] = 9999
        seen_queries.clear()
        out2 = self.fetch("--all", "--sources", "nvd", "--nvd", nvd_file, "--nvd-days", "200",
                          "--nvd-api", self.server.url + "/cves", "--nvd-delay", "0")
        self.assertIn("pubStartDate=2026-07-24T00%3A00%3A00.000Z", seen_queries[0])
        self.assertTrue(any(e["source"] == "nvd:fortios" and e.get("partial") for e in out2["errors"]))
        # a cut-off answer does not count as read in full
        write(nvd_file, "fortios|cpe:2.3:o:fortinet:fortios\npanos|cpe:2.3:o:paloaltonetworks:pan-os\n")
        self.fetch("--sources", "nvd", "--nvd", nvd_file, "--nvd-api", self.server.url + "/cves", "--nvd-delay", "0",
                   today="2026-11-21")
        self.assertNotIn("nvd:panos", load(self.state)["sources"])  # read next time with the first cut-off

    def test_nvd_old_cve_modified_again_is_not_news(self):
        payload = {"totalResults": 0, "vulnerabilities": []}
        self.server.pages["/cves"] = lambda q, h: json.dumps(payload)
        nvd = os.path.join(self.dir, "nvd.txt")
        write(nvd, "fortios|cpe:2.3:o:fortinet:fortios\n")
        args = ("--sources", "nvd", "--nvd", nvd, "--nvd-api", self.server.url + "/cves", "--nvd-delay", "0")
        self.fetch("--since", "2026-11-13", *args)
        self.run_tool("mark")
        payload.update(totalResults=1, vulnerabilities=[{"cve": {
            "id": "CVE-2019-0001", "published": "2019-05-01T00:00:00.000", "lastModified": "2026-11-20T00:00:00.000",
            "vulnStatus": "Modified", "descriptions": [], "metrics": {}}}])
        self.assertEqual(self.fetch(*args, today="2026-11-21")["items"], [])

    # ---------- CVE.org enrichment ----------

    def test_cve_details_enrichment(self):
        cve_record = {
            "cveMetadata": {"cveId": "CVE-2026-109618", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "affected": [{
                        "vendor": "PHP Group", "product": "PHP", "defaultStatus": "affected",
                        "versions": [{"version": "8.4.0", "lessThan": "8.4.28", "status": "affected"},
                                     {"version": "8.5.13", "status": "unaffected"}],
                    }],
                },
                "adp": [{
                    "metrics": [{"cvssV3_1": {
                        "baseScore": 9.2, "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                    }}],
                }],
            },
        }
        self.server.pages["/cve/CVE-2026-109618"] = json.dumps(cve_record)
        out = self.fetch("--since", "2026-11-01", "--sources", "zerowire,kev",
                         "--cve-details", "--cve-api", self.server.url + "/cve/")
        items = {i["key"]: i for i in out["items"]}
        kev_item = items["kev:CVE-2026-109618"]
        det = kev_item["cve_details"]["CVE-2026-109618"]
        self.assertEqual(det["score"], 9.2)
        self.assertEqual(det["severity"], "CRITICAL")
        self.assertIn("PHP Group / PHP: 8.4.0 < 8.4.28, fixed >= 8.5.13", det["affected"])
        # CVEs without a record in mock server produce partial cve_org errors without breaking items
        self.assertTrue(any(e["source"] == "cve_org" and e.get("partial") for e in out["errors"]))
        # respects --cve-details-max cap
        self.server.log.clear()
        self.fetch("--all", "--sources", "zerowire,kev", "--cve-details",
                   "--cve-details-max", "1", "--cve-api", self.server.url + "/cve/")
        cve_gets = [p for m, p in self.server.log if m == "GET" and p.startswith("/cve/")]
        self.assertEqual(len(cve_gets), 1)


    # ---------- 1.7.0: mark without delete, --strict, redirects, match, alert-prefilter ----------

    def test_mark_keep_snapshot_is_idempotent(self):
        self.fetch("--since", "2026-01-01")
        self.run_tool("mark", "--keep-snapshot")
        self.assertEqual(load(self.snap)["marked"], "2026-11-20")
        with open(self.state) as f:
            before = f.read()
        p = self.run_tool("mark", "--keep-snapshot", today="2026-11-21")
        self.assertIn("already marked", p.stderr)
        with open(self.state) as f:
            self.assertEqual(f.read(), before)  # a second mark changes nothing
        self.assertEqual(self.fetch()["items"], [])

    def test_mark_in_a_folder_that_forbids_deleting(self):
        import argparse
        import importlib.util
        import unittest.mock
        spec = importlib.util.spec_from_file_location("vuln_feed_t", SCRIPT)
        vf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vf)
        self.fetch("--since", "2026-01-01")
        a = argparse.Namespace(state=self.state, snapshot=self.snap, keep_snapshot=False)
        import contextlib
        import io
        err = io.StringIO()
        with unittest.mock.patch.object(vf.os, "remove", side_effect=PermissionError("Operation not permitted")), \
                contextlib.redirect_stderr(err):
            vf.cmd_mark(a, "2026-11-20")  # no exception: the state is saved, the snapshot is kept as marked
        self.assertIn("kept it", err.getvalue())
        self.assertEqual(load(self.state)["last_digest"], "2026-11-20")
        self.assertEqual(load(self.snap)["marked"], "2026-11-20")
        self.assertEqual(self.run_tool("mark").returncode, 0)

    def test_strict_exit_code(self):
        os.remove(self.kev)
        p = self.run_tool("fetch", "--since", "2026-01-01", "--strict", ok=False)
        self.assertEqual(p.returncode, 3, p.stderr)
        out = json.loads(p.stdout)  # the output and the snapshot are written all the same
        self.assertEqual([e["source"] for e in out["errors"]], ["kev"])
        self.assertTrue(os.path.exists(self.snap))
        self.assertEqual(self.run_tool("fetch").returncode, 0)  # without --strict: 0

    def test_check_feeds_shows_redirects(self):
        feeds = self.feeds_file(node=NODE_RSS)
        self.server.pages["/old.xml"] = (301, self.server.url + "/node.xml")
        self.server.pages["/moved-away.xml"] = (302, "http://localhost:9/feed.xml")
        with open(feeds, "a") as f:
            f.write(f"moved|{self.server.url}/old.xml\nblocked|{self.server.url}/moved-away.xml\n")
        rows = {r["name"]: r for r in json.loads(self.run_tool("check-feeds", "--feeds", feeds).stdout)}
        self.assertTrue(rows["moved"]["ok"])
        self.assertEqual(rows["moved"]["final_url"], self.server.url + "/node.xml")
        self.assertIn("moved", rows["moved"]["note"])
        self.assertFalse(rows["blocked"]["ok"])
        self.assertEqual(rows["blocked"]["hosts"], ["127.0.0.1", "localhost"])
        self.assertIn("the failed request went to localhost", rows["blocked"]["problems"][0])
        self.assertNotIn("redirects", rows["node"])

    def write_profile(self, text, name="profile.yaml"):
        path = os.path.join(self.dir, name)
        write(path, text)
        return path

    def test_profile_example_in_readme_parses(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("vuln_feed_t", SCRIPT)
        vf = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vf)
        with open(os.path.join(HERE, "..", "..", "README.md")) as f:
            readme = f.read()
        example = readme.split("# vuln-digest profile", 1)[1].split("```", 1)[0]
        prof = vf.load_profile(self.write_profile(example))
        self.assertEqual(prof["stack"][0], {"name": "nginx", "aliases": ["ingress-nginx", "NGINX Plus"], "exposed": True})
        self.assertEqual(prof["weekly_summary"]["day"], "monday")
        self.assertEqual(prof["schedule"], "weekdays 08:00")
        self.assertIsNone(prof["paused_until"])
        self.assertEqual(prof["stack_sources"][0]["repos"], ["acme/web-shop", "acme/infra"])
        block = vf.load_profile(self.write_profile(
            "stack:\n- name: Next.js\n  aliases:\n    - next\n  exposed: true\n- nginx\n"
            "boost: [ Linux kernel,\n  OpenSSL ]  # two lines\nurl: 'https://e.org/#x'\n"))
        self.assertEqual(block, {"stack": [{"name": "Next.js", "aliases": ["next"], "exposed": True}, "nginx"],
                                 "boost": ["Linux kernel", "OpenSSL"], "url": "https://e.org/#x"})
        self.assertEqual(vf.load_profile(self.write_profile('{"stack": ["nginx"]}', "p.json")), {"stack": ["nginx"]})
        with self.assertRaises(SystemExit):
            vf.load_profile(self.write_profile("notes: |\n  text\n"))

    def test_match(self):
        self.fetch("--since", "2026-01-01")
        prof = self.write_profile(
            "stack:\n  - { name: nginx, exposed: true }\n  - { name: Next.js, aliases: [next] }\n"
            "  - Cloudflare\n  - { name: Java, aliases: [OpenJDK] }\n"
            "ignore: [PHP]\npatched:\n  - { item: 'zerowire:java4shell', until: 2026-12-01, why: patched }\n")
        out = json.loads(self.run_tool("match", "--profile", prof).stdout)
        v = {m["key"]: m["verdict"] for m in out["items"]}
        self.assertEqual(v, {"zerowire:nginx2root": "focus", "zerowire:java4shell": "patched",
                             "kev:CVE-2026-109618": "ignored", "zerowire:old": "outside"})
        nginx = [m for m in out["items"] if m["key"] == "zerowire:nginx2root"][0]
        self.assertTrue(nginx["exposed"])
        self.assertTrue(any("'next'" in w for w in out["warnings"]))
        self.assertTrue(any("'Cloudflare' publishes the zerowire source" in w for w in out["warnings"]))
        # after the patched date the item is matched again
        out = json.loads(self.run_tool("match", "--profile", prof, today="2026-12-02").stdout)
        self.assertEqual({m["key"]: m["verdict"] for m in out["items"]}["zerowire:java4shell"], "focus")

    def test_alert_prefilter(self):
        pending = os.path.join(self.dir, "pending.json")
        quiet = self.write_profile("stack: [nginx]\n")  # nginx2root has no sign of exploitation
        p = self.run_tool("alert-prefilter", "--profile", quiet, "--pending", pending, "--since", "2026-01-01")
        self.assertEqual(json.loads(p.stdout)["candidates"], 0)
        self.assertEqual(load(pending)["candidates"], [])
        self.assertEqual(load(self.state)["last_digest"], "2026-11-20")  # marked without the agent
        self.assertFalse(os.path.exists(self.snap))
        # the KEV entry for PHP is exploited and in focus: the agent is needed, nothing is marked
        os.remove(self.state)
        hot = self.write_profile("stack: [PHP]\n")
        p = self.run_tool("alert-prefilter", "--profile", hot, "--pending", pending, "--since", "2026-01-01", ok=False)
        self.assertEqual(p.returncode, 10, p.stderr)
        cands = load(pending)["candidates"]
        self.assertEqual([c["key"] for c in cands], ["kev:CVE-2026-109618"])
        self.assertEqual(cands[0]["match"]["verdict"], "focus")
        self.assertTrue(os.path.exists(self.snap))
        self.assertIsNone(load(self.state)["last_digest"])
        self.run_tool("mark")  # the agent sent the alert and marked
        p = self.run_tool("alert-prefilter", "--profile", hot, "--pending", pending)
        self.assertEqual(json.loads(p.stdout)["items"], 0)
        # a pause with pause_alerts: no fetch at all
        paused = self.write_profile("stack: [PHP]\npaused_until: 2026-12-01\npause_alerts: true\n")
        p = self.run_tool("alert-prefilter", "--profile", paused, "--pending", pending)
        self.assertEqual(load(pending)["paused_until"], "2026-12-01")

    # ---------- 1.8.0: --reuse-if-fresh, --osv-max, ignore descriptions ----------

    def test_alert_prefilter_reuse_if_fresh(self):
        pending = os.path.join(self.dir, "pending.json")
        hot = self.write_profile("stack: [PHP]\n")
        args = ("alert-prefilter", "--profile", hot, "--pending", pending)
        p = self.run_tool(*args, "--since", "2026-01-01", ok=False)  # the local scheduler's run
        self.assertEqual(p.returncode, 10, p.stderr)
        os.remove(self.kev)  # the agent's run must not fetch: a fetch would now report an error
        p = self.run_tool(*args, "--reuse-if-fresh", "90", ok=False)
        self.assertEqual(p.returncode, 10, p.stderr)
        self.assertEqual(json.loads(p.stdout)["candidates"], 1)
        self.assertEqual(len(load(pending)["candidates"]), 1)
        self.run_tool("mark")  # the agent sent the alert
        # a later agent run before the next prefilter run: the same alert is not sent again
        p = self.run_tool(*args, "--reuse-if-fresh", "90")
        out = json.loads(p.stdout)
        self.assertEqual((out["candidates"], out["already_marked"]), (0, True))
        # a stale pending file (the computer slept): the agent fetches itself
        pend = load(pending)
        pend["checked"] = "2026-01-01T00:00:00+00:00"
        write(pending, json.dumps(pend))
        p = self.run_tool(*args, "--reuse-if-fresh", "90", ok=False)
        self.assertNotIn("reused", json.loads(p.stdout))
        self.assertEqual(load(pending)["errors"][0]["source"], "kev")

    def test_osv_max(self):
        vulns = {f"GHSA-{n}": osv_vuln(f"GHSA-{n}", affected=[affected("npm", "next", "16.4.1")]) for n in "abc"}
        self.osv_server(vulns, [{"vulns": [{"id": k, "modified": v["modified"]} for k, v in vulns.items()]}])
        out = self.osv("npm|next|16.2.0\n", "--all", "--osv-max", "2")
        self.assertEqual(len(out["items"]), 2)
        self.assertEqual(out["errors"][0]["error"], "1 advisory(ies) not downloaded: --osv-max 2")
        self.assertTrue(out["errors"][0]["partial"])

    def test_match_warns_about_descriptive_ignore(self):
        self.fetch("--since", "2026-01-01")
        prof = self.write_profile(
            'stack: [nginx, Ubuntu]\n'
            'ignore:\n  - Android/iOS/ChromeOS-only Chrome releases\n  - Windows: local privilege escalation\n  - PHP\n'
            'boost: ["quoted [bracket] # not comment"]\n')
        out = json.loads(self.run_tool("match", "--profile", prof).stdout)
        self.assertTrue(any("'Android/iOS/ChromeOS-only Chrome releases' looks like a description" in w
                            for w in out["warnings"]))
        self.assertTrue(any("'Windows: local privilege escalation' looks like a description" in w
                            for w in out["warnings"]))
        self.assertFalse(any("'PHP'" in w for w in out["warnings"]))
        # Umbrella OS feed (feeds:ubuntu) matching only "Ubuntu" gives maybe; matching nginx too gives focus
        snap_in = os.path.join(self.dir, "umb.json")
        write(snap_in, json.dumps({"items": [
            {"key": "feed:ubuntu:usn-1", "source": "feeds:ubuntu", "title": "USN-1: Thunderbird bug",
             "summary": "Ubuntu Security Notice", "cves": ["CVE-2026-1"]},
            {"key": "feed:ubuntu:usn-2", "source": "feeds:ubuntu", "title": "USN-2: nginx bug",
             "summary": "Ubuntu Security Notice", "cves": ["CVE-2026-2"], "fixed_versions": ["1.24.0-2ubuntu1"]},
        ]}))
        out_umb = json.loads(self.run_tool("match", "--profile", prof, "--input", snap_in).stdout)
        by_k = {m["key"]: m for m in out_umb["items"]}
        self.assertEqual(by_k["feed:ubuntu:usn-1"]["verdict"], "maybe")
        self.assertEqual(by_k["feed:ubuntu:usn-2"]["verdict"], "focus")
        self.assertEqual(by_k["feed:ubuntu:usn-2"]["fixed_versions"], ["1.24.0-2ubuntu1"])

    def test_blocked_hosts_and_error_host(self):
        feeds = os.path.join(self.dir, "feeds.txt")
        write(feeds, f"dead|{self.server.url}/missing.xml\n")
        prof = self.write_profile("stack: [nginx]\nblocked_hosts: [127.0.0.1]\n")
        # Without blocked_hosts profile, --strict exits 3; with blocked_hosts matching 127.0.0.1, exits 0
        p1 = self.run_tool("fetch", "--all", "--sources", "feeds", "--feeds", feeds, "--strict", ok=False)
        self.assertEqual(p1.returncode, 3)
        err1 = json.loads(p1.stdout)["errors"][0]
        self.assertEqual(err1["host"], "127.0.0.1")
        p2 = self.run_tool("fetch", "--all", "--sources", "feeds", "--feeds", feeds, "--profile", prof, "--strict")
        self.assertEqual(p2.returncode, 0)
        self.assertTrue(json.loads(p2.stdout)["errors"][0]["blocked"])

if __name__ == "__main__":
    unittest.main()
