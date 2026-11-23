"""Offline tests for vuln_stack.py and catalog.json. Run from the repository root: python3 -I -m unittest discover -s tools/tests"""
import http.server
import json
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "vuln_stack.py")
CATALOG = os.path.join(HERE, "..", "catalog.json")
NO_PROXY_ENV = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def lines(path):
    with open(path) as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


class QuickServer(http.server.ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


class Server:
    def __init__(self):
        self.pages, self.log, self.headers = {}, [], []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.log.append(self.path)
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                outer.headers.append(hdrs)
                base, _, query = self.path.partition("?")
                page = outer.pages.get(self.path)
                if page is None:
                    page = outer.pages.get(base)
                if callable(page):
                    page = page(query, hdrs)
                if page is None:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(page if isinstance(page, bytes) else page.encode())

            def log_message(self, *args):
                pass

        self.httpd = QuickServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class VulnStackTest(unittest.TestCase):
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

    def tearDown(self):
        shutil.rmtree(self.dir)

    def run_tool(self, *args, ok=True, stdin=None, env=None):
        cmd = [sys.executable, "-I", SCRIPT, *args]
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True,
                           env={**NO_PROXY_ENV, **(env or {})})
        if ok:
            self.assertEqual(p.returncode, 0, p.stderr)
        return p

    def test_scan_npm_dev_private_and_suspects_fail_closed(self):
        lock = {
            "name": "web-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "web-app", "version": "1.0.0"},
                "node_modules/express": {
                    "version": "4.21.1",
                    "resolved": "https://registry.npmjs.org/express/-/express-4.21.1.tgz",
                },
                "node_modules/jest": {
                    "version": "29.7.0",
                    "dev": True,
                    "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz",
                },
                "node_modules/local-lib": {
                    "resolved": "packages/local-lib",
                    "link": True,
                },
                "node_modules/internal-sdk": {
                    "version": "1.2.0",
                    "resolved": "https://npm.corp.internal/internal-sdk/-/internal-sdk-1.2.0.tgz",
                },
                "node_modules/@aws-sdk/client-s3": {
                    "version": "3.650.0",
                    "resolved": "https://registry.npmjs.org/@aws-sdk/client-s3/-/client-s3-3.650.0.tgz",
                },
                "node_modules/@acme/ui": {
                    "version": "2.0.0",
                    "resolved": "https://registry.npmjs.org/@acme/ui/-/ui-2.0.0.tgz",
                },
                "node_modules/@acme/auth": {
                    "version": "2.1.0",
                    "resolved": "https://registry.npmjs.org/@acme/auth/-/auth-2.1.0.tgz",
                },
            },
        }
        write(os.path.join(self.dir, "package-lock.json"), json.dumps(lock))
        out_pkg = os.path.join(self.dir, "packages.txt")
        out_dev = os.path.join(self.dir, "packages-dev.txt")
        rep = json.loads(self.run_tool("scan", self.dir, "--out", out_pkg, "--dev-out", out_dev).stdout)
        self.assertEqual(lines(out_pkg), ["npm|express|4.21.1"])
        self.assertEqual(lines(out_dev), ["npm|jest|29.7.0"])
        self.assertEqual(rep["skipped_dev"], 1)
        self.assertEqual(rep["skipped_private"], 2)  # local-lib + internal-sdk
        suspects = {s["scope"]: s["count"] for s in rep["suspects"]}
        self.assertEqual(suspects, {"@acme": 2, "@aws-sdk": 1})

        # Approve @aws-sdk and explicitly exclude @acme/
        rep2 = json.loads(self.run_tool("scan", self.dir, "--out", out_pkg,
                                        "--allow-scope", "@aws-sdk", "--exclude-prefix", "@acme/").stdout)
        self.assertEqual(lines(out_pkg), ["npm|@aws-sdk/client-s3|3.650.0", "npm|express|4.21.1"])
        self.assertEqual(rep2["suspects"], [])

    def test_scan_multiple_lockfiles_sbom_and_runtimes(self):
        # CycloneDX SBOM
        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3"},
                {"name": "log4j-core", "version": "2.24.0",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.24.0"},
            ],
        }
        write(os.path.join(self.dir, "bom.cdx.json"), json.dumps(cdx))
        # SPDX SBOM
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "serde",
                "versionInfo": "1.0.210",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:cargo/serde@1.0.210"}],
            }],
        }
        write(os.path.join(self.dir, "app.spdx.json"), json.dumps(spdx))
        # Go
        write(os.path.join(self.dir, "go.mod"),
              "module github.com/acme/web\n\ngo 1.23.2\n\nreplace github.com/acme/shared => ./shared\n")
        write(os.path.join(self.dir, "go.sum"),
              "github.com/gin-gonic/gin v1.10.0 h1:aaa\n"
              "github.com/gin-gonic/gin v1.10.0/go.mod h1:bbb\n"
              "github.com/acme/web/pkg v0.1.0 h1:ccc\n"
              "git.corp.internal/team/auth v1.2.3 h1:ddd\n")
        # Composer
        write(os.path.join(self.dir, "composer.lock"), json.dumps({
            "packages": [
                {"name": "symfony/http-kernel", "version": "v7.1.5", "source": {"type": "git", "url": "https://github.com/symfony/http-kernel"}},
                {"name": "acme/local", "version": "1.0.0", "dist": {"type": "path", "url": "../local"}},
            ],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "11.3.0"}],
        }))
        # Cargo
        write(os.path.join(self.dir, "Cargo.lock"),
              '[[package]]\nname = "tokio"\nversion = "1.40.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n'
              '[[package]]\nname = "my-app"\nversion = "0.1.0"\n')
        # Poetry & uv
        write(os.path.join(self.dir, "poetry.lock"),
              '[[package]]\nname = "urllib3"\nversion = "2.2.3"\ngroups = ["main"]\n\n'
              '[[package]]\nname = "ruff"\nversion = "0.7.0"\ngroups = ["dev"]\n\n'
              '[[package]]\nname = "local-mod"\nversion = "0.1.0"\n[package.source]\ntype = "directory"\n')
        write(os.path.join(self.dir, "uv.lock"),
              '[[package]]\nname = "httpx"\nversion = "0.27.2"\nsource = { registry = "https://pypi.org/simple" }\n\n'
              '[[package]]\nname = "my-proj"\nversion = "0.1.0"\nsource = { virtual = "." }\n')
        # requirements + dev
        write(os.path.join(self.dir, "requirements.txt"), "Flask[async]==3.1.0 ; python_version >= '3.9'\n-r other.txt\n")
        write(os.path.join(self.dir, "requirements-dev.txt"), "pytest==8.3.3\n")
        # Gemfile.lock
        write(os.path.join(self.dir, "Gemfile.lock"),
              "PATH\n  remote: .\n  specs:\n    localgem (1.0.0)\n\n"
              "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.8)\n      base64\n")
        # NuGet packages.lock.json + csproj
        write(os.path.join(self.dir, "packages.lock.json"), json.dumps({
            "version": 1,
            "dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}}},
        }))
        write(os.path.join(self.dir, "app.csproj"),
              '<Project><ItemGroup><PackageReference Include="Serilog" Version="4.0.2" /></ItemGroup></Project>')
        # Maven pom.xml
        write(os.path.join(self.dir, "pom.xml"),
              '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>'
              '<dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>33.3.1-jre</version></dependency>'
              '<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version><scope>test</scope></dependency>'
              '<dependency><groupId>org.foo</groupId><artifactId>bar</artifactId><version>${bar.version}</version></dependency>'
              '</dependencies></project>')
        # Unsupported lockfile
        write(os.path.join(self.dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n")
        # Runtimes & Dockerfile
        write(os.path.join(self.dir, "Dockerfile"),
              "FROM node:22-alpine AS build\nFROM build AS test\nFROM scratch\nFROM nginx:1.27.2-alpine\n")
        write(os.path.join(self.dir, ".nvmrc"), "v22.11.0\n")
        write(os.path.join(self.dir, ".python-version"), "3.12.7\n")
        write(os.path.join(self.dir, "global.json"), json.dumps({"sdk": {"version": "8.0.403"}}))
        write(os.path.join(self.dir, ".tool-versions"), "ruby 3.3.5\n")
        # Ignored vendor dir
        write(os.path.join(self.dir, "node_modules", "ignored", "requirements.txt"), "evil==0.0.1\n")

        out_pkg = os.path.join(self.dir, "packages.txt")
        rep = json.loads(self.run_tool("scan", self.dir, "--out", out_pkg).stdout)
        got = set(lines(out_pkg))
        expected = {
            "PyPI|requests|2.32.3",
            "Maven|org.apache.logging.log4j:log4j-core|2.24.0",
            "crates.io|serde|1.0.210",
            "Go|github.com/gin-gonic/gin|1.10.0",
            "Packagist|symfony/http-kernel|7.1.5",
            "crates.io|tokio|1.40.0",
            "PyPI|urllib3|2.2.3",
            "PyPI|httpx|0.27.2",
            "PyPI|Flask|3.1.0",
            "RubyGems|rack|3.1.8",
            "NuGet|Newtonsoft.Json|13.0.3",
            "NuGet|Serilog|4.0.2",
            "Maven|com.google.guava:guava|33.3.1-jre",
        }
        self.assertEqual(got, expected)
        self.assertEqual([u["file"] for u in rep["unsupported_files"]], ["pnpm-lock.yaml"])
        self.assertEqual({s["scope"] for s in rep["suspects"]}, {"git.corp.internal"})
        rt_names = {(r["name"], r["version"]) for r in rep["runtimes"]}
        self.assertTrue({("node", "22-alpine"), ("nginx", "1.27.2-alpine"), ("go", "1.23.2"),
                         ("node", "22.11.0"), ("python", "3.12.7"), (".net", "8.0.403"), ("ruby", "3.3.5")} <= rt_names)
        self.assertFalse(any(r["name"] in ("build", "scratch") for r in rep["runtimes"]))

    def test_scan_stdin_and_diff(self):
        old_pkg = os.path.join(self.dir, "old.txt")
        write(old_pkg, "PyPI|flask|3.0.0\nPyPI|removed-pkg|1.0.0\n")
        rep = json.loads(self.run_tool("scan", "--stdin", "--format", "requirements.txt", "--diff", old_pkg,
                                       stdin="flask==3.1.0\nrequests==2.32.3\n").stdout)
        self.assertEqual(rep["diff"]["added"], ["PyPI|requests|2.32.3"])
        self.assertEqual(rep["diff"]["removed"], ["PyPI|removed-pkg|1.0.0"])
        self.assertEqual(rep["diff"]["updated"], [{"package": "PyPI|flask", "old": "3.0.0", "new": "3.1.0"}])

    def test_suggest_sources_and_catalog_schema(self):
        with open(CATALOG) as f:
            cat = json.load(f)
        ids = [e["id"] for e in cat["entries"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate catalog ids")
        self.assertGreaterEqual(len(ids), 25)
        for e in cat["entries"]:
            self.assertTrue(e["id"] and e["name"] and e["kind"] and e["sources"])
            for s in e["sources"]:
                if s["type"] == "feed":
                    self.assertTrue(s["url"].startswith("https://"), s)
                elif s["type"] == "ghsa":
                    self.assertRegex(s["repo"], r"^[\w.-]+/[\w.-]+$")
                elif s["type"] == "nvd":
                    self.assertTrue(s["cpe"].startswith("cpe:2.3:"), s)
                else:
                    self.fail(f"unknown source type: {s}")

        out = json.loads(self.run_tool("suggest-sources", "--stack", "nginx,k8s,FortiGate,php,mystery-box").stdout)
        self.assertIn("kubernetes|https://kubernetes.io/docs/reference/issues-security/official-cve-feed/feed.xml", out["feeds"])
        self.assertIn("php/php-src", out["ghsa"])
        self.assertIn("nginx|cpe:2.3:a:f5:nginx", out["nvd"])
        self.assertIn("fortios|cpe:2.3:o:fortinet:fortios", out["nvd"])
        self.assertEqual(out["unmatched"], ["mystery-box"])

    def test_discover_feeds(self):
        page = (
            '<!doctype html><html><head>'
            '<link rel="alternate" type="application/rss+xml" title="Security RSS" href="/security/feed.xml">'
            '<link rel="alternate" type="application/atom+xml" title="Atom" href="https://vendor.example/sec.atom">'
            '</head><body>'
            '<a href="https://github.com/acme/proxy/security/advisories">Advisories</a>'
            '<a href="javascript:void(0)">Ignore</a>'
            '</body></html>'
        )
        self.server.pages["/security"] = page
        out = json.loads(self.run_tool("discover-feeds", self.server.url + "/security").stdout)
        feed_urls = {f["url"] for f in out["feeds"]}
        self.assertEqual(feed_urls, {self.server.url + "/security/feed.xml", "https://vendor.example/sec.atom"})
        self.assertEqual(out["ghsa_repos"], ["acme/proxy"])
        p = self.run_tool("discover-feeds", "file:///etc/passwd", ok=False)
        self.assertNotEqual(p.returncode, 0)

    def test_find_cpe(self):
        payload = {
            "products": [
                {"cpe": {"cpeName": "cpe:2.3:o:fortinet:fortios:7.2.10:*:*:*:*:*:*:*", "deprecated": False,
                         "titles": [{"lang": "en", "title": "Fortinet FortiOS 7.2.10"}]}},
                {"cpe": {"cpeName": "cpe:2.3:o:fortinet:fortios:7.4.5:*:*:*:*:*:*:*", "deprecated": False,
                         "titles": [{"lang": "en", "title": "Fortinet FortiOS 7.4.5"}]}},
                {"cpe": {"cpeName": "cpe:2.3:o:fortinet:fortios:5.0.0:*:*:*:*:*:*:*", "deprecated": True,
                         "titles": [{"lang": "en", "title": "Old"}]}},
                {"cpe": {"cpeName": "cpe:2.3:a:fortinet:forticlient:7.2.0:*:*:*:*:*:*:*", "deprecated": False,
                         "titles": [{"lang": "en", "title": "Fortinet FortiClient 7.2.0"}]}},
            ]
        }
        seen_key = []

        def serve(query, hdrs):
            seen_key.append(hdrs.get("apikey"))
            self.assertIn("keywordSearch=fortios", query)
            return json.dumps(payload)

        self.server.pages["/cpes"] = serve
        out = json.loads(self.run_tool("find-cpe", "fortios", "--nvd-cpe-api", self.server.url + "/cpes",
                                       env={"NVD_API_KEY": "example"}).stdout)
        self.assertEqual(seen_key, ["example"])
        self.assertEqual(out["prefixes"][0]["cpe"], "cpe:2.3:o:fortinet:fortios")
        self.assertEqual(out["prefixes"][0]["matches"], 2)  # deprecated excluded


if __name__ == "__main__":
    unittest.main()
