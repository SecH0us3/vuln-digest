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
    """A local HTTP server for feeds and the OSV API. pages: path -> bytes, or a callable(body) -> bytes"""

    def __init__(self):
        self.pages, self.log = {}, []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def answer(self, body=None):
                outer.log.append((self.command, self.path))
                page = outer.pages.get(self.path)
                if callable(page):
                    page = page(body)
                if page is None:
                    self.send_error(404)
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

    def run_tool(self, *args, ok=True, today="2026-11-20"):
        cmd = [sys.executable, "-I", SCRIPT, *args, "--state", self.state, "--snapshot", self.snap,
               "--zerowire-file", self.zw, "--kev-file", self.kev, "--today", today]
        p = subprocess.run(cmd, capture_output=True, text=True, env=NO_PROXY_ENV)
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


if __name__ == "__main__":
    unittest.main()
