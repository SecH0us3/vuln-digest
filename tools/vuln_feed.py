#!/usr/bin/env python3
"""vuln_feed.py - collect new and updated vulnerability items for a digest, without repeats.

Part of vuln-digest: https://vuln-digest.secmy.app/
Python 3.9+, standard library only. Read this file before you run it.

Sources:
  zerowire  Cloudflare Radar Zero Wire briefings (RSS)
  kev       CISA Known Exploited Vulnerabilities catalog (JSON)
  osv       OSV.dev advisories for the packages listed in --packages
  feeds     any RSS or Atom feeds listed in --feeds (vendor security bulletins)
  ghsa      GitHub Security Advisories for repos/ecosystems in --ghsa (optional GITHUB_TOKEN env)
  nvd       NVD CVE 2.0 advisories for CPEs listed in --nvd (optional NVD_API_KEY env)

How repeats are avoided:
  every item has a key (zerowire:<slug>, kev:<CVE>, osv:<ID>) and a list of
  fingerprints of its updates. An item is shown when its key is new, or when it
  has a fingerprint that was not shown before. A guid or a "last reviewed" date
  that changes alone does not make an update. When a CVE of a known item enters
  the KEV catalog, the item gets a new update "added to CISA KEV". A vendor feed
  entry whose title or CVE list changes gets the update "advisory changed"

New sources:
  the state remembers which sources were read in full. A source read for the first
  time (a new feed, or one that failed on the first run) does not flood the digest
  with its archive: its updates dated before the last digest count as seen

Usage:
  python3 -I vuln_feed.py fetch [--sources zerowire,kev,feeds,osv,ghsa,nvd] [--packages FILE] [--feeds FILE] [--ghsa FILE] [--nvd FILE] [--epss] [--cve-details]
      print new and updated items as JSON and save them to the snapshot file
  python3 -I vuln_feed.py mark
      mark exactly the items of the snapshot as delivered. Does not fetch again.
      Run it only after the digest was delivered
  python3 -I vuln_feed.py fetch --since YYYY-MM-DD
      no state file yet: treat every update dated before this day as already seen.
      With a state file, it sets the cut-off for sources that are read for the first time
  python3 -I vuln_feed.py fetch --all
      everything the sources hold now, state is not read or changed (preview)
  python3 -I vuln_feed.py history [--days 28]
      items delivered in the last N days, newest first: for the weekly summary
      and for "I patched X" feedback
  python3 -I vuln_feed.py check-feeds --feeds FILE
      read each feed once and say whether it works: its format, entries, newest
      date and CVE ids. For the setup, before a feed goes into the job

Files (next to this script unless set): state.json, last_run.json
Offline testing: --zerowire-file, --kev-file, --osv-file read local copies
Items that share a CVE get "same_cve_items" (other keys in this run) and
"cves_delivered_in" (CVE -> key of an item already delivered): merge them in the digest
"""
import argparse
import datetime
import hashlib
import html
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

VERSION = "1.5.0"
UA = f"vuln-digest/{VERSION} (+https://vuln-digest.secmy.app/)"
ZEROWIRE_FEED = "https://radar.cloudflare.com/zero-wire/feed"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_API = "https://api.osv.dev/v1/"
GHSA_API = "https://api.github.com/"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_API = "https://cveawg.mitre.org/api/cve/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
HERE = os.path.dirname(os.path.abspath(__file__))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
STATE_VERSION = 4
MAX_BYTES = 32 * 1024 * 1024  # a larger response is refused


def fp(*parts):
    # an identifier for deduplication, not a security control
    return hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:16]


def web_url(url):
    """Only http and https go to urlopen. Other schemes, such as file: or ftp:, are refused"""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"not an http(s) URL: {url!r}")
    return url


# S310: urlopen gets only URLs that web_url() checked
def http_get(url, timeout=60, data=None, extra_headers=None):
    headers = {"User-Agent": UA}
    if extra_headers:
        headers.update(extra_headers)
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(web_url(url), data=data, headers=headers)  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"response larger than {MAX_BYTES} bytes: {url}")
    return body


def http_post_json(url, obj, timeout=60):
    return json.loads(http_get(url, timeout, json.dumps(obj).encode()))


def data_lines(path):
    """Lines of a list file. # starts a comment at the start of a line or after a space,
    so a # inside a URL stays"""
    with open(path) as f:
        for line in f:
            line = re.sub(r"(^|\s)#.*", "", line).strip()
            if line:
                yield line


def strip_html(s):
    s = re.sub(r"<(br|/p|/li|/h\d)[^>]*>", "\n", s or "")
    s = re.sub(r"<li[^>]*>", "- ", s)
    s = re.sub(r"<[^>]+>", "", s)
    s = html.unescape(s)
    return re.sub(r"\n\s*\n+", "\n", s).strip()


# ---------- Zero Wire ----------

def zerowire_updates(content):
    m = re.search(r"<h2[^>]*>\s*Updates\s*</h2>\s*<ul>(.*?)</ul>", content, re.S)
    out = []
    for li in re.findall(r"<li>(.*?)</li>", m.group(1), re.S) if m else []:
        d = re.search(r'<time datetime="([^"]+)"', li)
        stamp = d.group(1) if d else ""
        text = re.sub(r"^.*?</time>\s*:?\s*", "", li, count=1, flags=re.S) if d else li
        text = re.sub(r"\s+", " ", strip_html(text)).strip()
        # the fingerprint uses the full timestamp: the same formula as the prototype's state v2
        out.append({"date": stamp[:10], "text": text, "id": fp(stamp, text)})
    return out


def lname(el):
    """The tag without its namespace: RSS 2.0, RSS 1.0 (RDF) and Atom name the same things differently"""
    return el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""


def ctext(el, *names):
    """Text of the first child whose local name is in names, tried in that order. Includes nested
    elements, such as the XHTML inside Atom <content type="xhtml">"""
    for n in names:
        for c in el:
            text = " ".join(c.itertext())  # a space between tags: <p>CVE-2026-1</p><p>2 steps</p>
            if lname(c) == n and text.strip():
                return text
    return ""


# S314: xml.etree does not load external entities or DTDs, and expat 2.4.1 or later limits
# entity expansion, so feed XML from the network is safe to parse here
def feed_entries(raw):
    """<item> (RSS 2.0, RSS 1.0) and <entry> (Atom) elements in any namespace.
    A feed cut off in transfer still gives its complete entries"""
    try:
        root = ET.fromstring(raw)  # noqa: S314
        entries = [e for e in root.iter() if lname(e) in ("item", "entry")]
        if not entries and lname(root) not in ("rss", "RDF", "feed"):
            raise ValueError(f"not an RSS or Atom feed: the root element is <{lname(root)}>")
        return entries, None
    except ET.ParseError as e:
        text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
        ns = " ".join(f'{k}="{v}"' for k, v in dict(re.findall(r'(xmlns(?::\w+)?)="([^"]*)"', text[:4000])).items())
        items = []
        for m in re.finditer(r"<((?:\w+:)?(?:item|entry))\b.*?</\1>", text, re.S):
            try:
                items.append(ET.fromstring(f"<x {ns}>{m.group(0)}</x>")[0])  # noqa: S314
            except ET.ParseError:
                continue
        if not items:
            raise
        return items, f"feed is not well-formed ({e}); {len(items)} complete item(s) were read, the rest is skipped"


def parse_zerowire(raw, warnings=None):
    elements, warning = feed_entries(raw)
    if warning and warnings is not None:
        warnings.append(warning)
    items = []
    for it in elements:
        guid = ctext(it, "guid", "link")
        desc = ctext(it, "description")
        content = ctext(it, "encoded")
        date = feed_date(ctext(it, "pubDate"))
        slug = guid.split("@")[0].rstrip("/").split("/")[-1]
        updates = zerowire_updates(content)
        if not updates:  # "legacy": the prototype fingerprinted such items by guid
            updates = [{"date": date, "text": "published", "id": fp("published", slug),
                        "legacy": hashlib.sha1(guid.encode(), usedforsecurity=False).hexdigest()[:16]}]
        items.append({
            "key": f"zerowire:{slug}",
            "source": "zerowire",
            "title": ctext(it, "title"),
            "link": ctext(it, "link"),
            "date": date,
            "summary": strip_html(desc),
            "cves": sorted(set(CVE_RE.findall(content + " " + desc))),
            "updates": updates,
            "text": strip_html(content)[:8000],
        })
    return items


# ---------- vendor feeds (RSS 2.0, RSS 1.0 or Atom) ----------

def read_feeds(path):
    """One feed per line: name|url"""
    out = []
    for line in data_lines(path):
        name, _, url = (p.strip() for p in line.partition("|"))
        if not (name and url):
            raise SystemExit(f"bad feed line: {line!r} (expected name|url)")
        out.append((name, url))
    return out


def feed_date(text):
    """YYYY-MM-DD from an RFC 822 or ISO 8601 date, or "" if the date cannot be read"""
    text = (text or "").strip()
    if re.match(r"\d{4}-\d{2}-\d{2}", text):
        return text[:10]
    try:
        return parsedate_to_datetime(text).date().isoformat()
    except (TypeError, ValueError, IndexError):
        return ""


def entry_link(e):
    """RSS <link>text</link>, or the Atom <link href> with rel="alternate" (the default rel)"""
    for c in e:
        if lname(c) == "link":
            if (c.text or "").strip():
                return c.text.strip()
            if c.get("rel", "alternate") == "alternate" and c.get("href"):
                return c.get("href")
    return ""


def parse_vendor_feed(name, raw, warnings=None):
    """Each entry is one item. Its key is the feed name plus the entry id or link.
    "sig" changes when the title or the CVE list changes: fetch turns that into an update"""
    entries, warning = feed_entries(raw)
    if warning and warnings is not None:
        warnings.append(warning)
    items = []
    for e in entries:
        title = ctext(e, "title").strip()
        link = entry_link(e)
        ident = ctext(e, "guid", "id") or e.get("{http://www.w3.org/1999/02/22-rdf-syntax-ns#}about") or link or title
        date = feed_date(ctext(e, "pubDate", "updated", "published", "date"))
        body = ctext(e, "encoded", "content", "description", "summary")  # the full text first
        text = strip_html(body)
        cves = sorted(set(CVE_RE.findall(" ".join([title, body, ctext(e, "description", "summary")]))))
        items.append({
            "key": f"feed:{name}:{ident}",
            "source": f"feeds:{name}",
            "title": title,
            "link": link,
            "date": date,
            "summary": text[:1500],
            "cves": cves,
            "sig": fp(title, *cves),
            "updates": [{"date": date, "text": "published", "id": fp("feed", name, ident)}],
            "text": text[:8000],
        })
    return items


def check_feed(name, url):
    """One line of check-feeds. "problems" lists what makes the feed useless for a digest"""
    row = {"name": name, "url": url, "ok": False, "problems": []}
    try:
        raw = http_get(url)
    except Exception as e:
        row["problems"].append(f"{type(e).__name__}: {e}")  # an HTTP error names its status
        return row
    head = raw[:500].decode("utf-8", "replace").lstrip().lower()
    if head.startswith(("<!doctype html", "<html")):
        row["problems"].append("an HTML page, not a feed: look for the RSS or Atom link on it")
        return row
    try:
        root = ET.fromstring(raw)  # noqa: S314 - safe for the same reason as in feed_entries
        row["format"] = {"rss": "RSS 2.0", "RDF": "RSS 1.0", "feed": "Atom"}.get(lname(root), lname(root))
    except ET.ParseError as e:
        row["format"] = f"not well-formed XML ({e})"
    warnings = []
    try:
        items = parse_vendor_feed(name, raw, warnings)
    except (ET.ParseError, ValueError) as e:
        items = []
        row["problems"].append(str(e))
    dates = sorted(i["date"] for i in items if i["date"])
    row.update(entries=len(items), newest=dates[-1] if dates else "",
               with_cve=sum(1 for i in items if i["cves"]), undated=len(items) - len(dates))
    row["problems"] += warnings
    if not items:
        row["problems"].append("no entries")
    elif not row["with_cve"]:
        row["problems"].append("no entry names a CVE: is this a security feed, or a blog?")
    if row["undated"]:
        row["problems"].append(f"{row['undated']} entries without a readable date")
    row["latest"] = [i["title"] for i in sorted(items, key=lambda i: i["date"], reverse=True)[:3]]
    row["ok"] = not row["problems"]
    return row


# ---------- CISA KEV ----------

def parse_kev(raw):
    data = json.loads(raw)
    items = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        added = v.get("dateAdded", "")
        items.append({
            "key": f"kev:{cve}",
            "source": "kev",
            "title": v.get("vulnerabilityName") or cve,
            "link": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "date": added,
            "summary": v.get("shortDescription", ""),
            "cves": [cve],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "kev": {"date_added": added, "due_date": v.get("dueDate", ""),
                    "ransomware": v.get("knownRansomwareCampaignUse", ""),
                    "required_action": v.get("requiredAction", "")},
            "updates": [{"date": added, "text": "added to CISA KEV", "id": fp("kev", cve)}],
            "text": v.get("notes", ""),
        })
    return items


# ---------- OSV ----------

def read_packages(path):
    """One package per line: ecosystem|name|version  (version may be empty)"""
    out = []
    for line in data_lines(path):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) < 2:
            raise SystemExit(f"bad package line: {line!r} (expected ecosystem|name|version)")
        out.append({"ecosystem": parts[0], "name": parts[1], "version": parts[2] if len(parts) > 2 else ""})
    return out


def same_package(affected, pkg):
    """Does an "affected" entry of an advisory name this package? Debian:12 matches Debian:12 exactly,
    Debian matches any Debian release. PyPI names compare as PyPI normalizes them"""
    eco, want = affected.get("ecosystem", "").lower(), pkg["ecosystem"].lower()
    if eco != want and (":" in want or eco.split(":")[0] != want):
        return False
    norm = (lambda n: re.sub(r"[-_.]+", "-", n.lower())) if want == "pypi" else str.lower
    return norm(affected.get("name", "")) == norm(pkg["name"])


def osv_fixed(vuln, pkgs):
    """Fixed versions of the user's packages only: one advisory can cover other packages and distributions"""
    fixed = set()
    for a in vuln.get("affected", []):
        if any(same_package(a.get("package", {}), p) for p in pkgs):
            for r in a.get("ranges", []):
                fixed.update(e["fixed"] for e in r.get("events", []) if "fixed" in e)
    return sorted(fixed)


def osv_rev(modified, pkgs):
    """Changes when the advisory or the matching packages change"""
    return fp(modified, *(f"{p['ecosystem']}|{p['name']}|{p['version']}" for p in pkgs))


def osv_item(vuln, pkgs):
    vid = vuln.get("id", "")
    date = (vuln.get("published") or vuln.get("modified") or "")[:10]
    fixed = osv_fixed(vuln, pkgs)
    item = {
        "key": f"osv:{vid}",
        "source": "osv",
        "title": vuln.get("summary") or vid,
        "link": f"https://osv.dev/vulnerability/{vid}",
        "date": date,
        "summary": (vuln.get("details") or "")[:1500],
        "cves": sorted({a for a in [vid, *vuln.get("aliases", [])] if a.startswith("CVE-")}),
        "package": pkgs[0],
        "packages": pkgs,  # every package from the packages file that this advisory affects
        "fixed_versions": fixed,
        "severity": vuln.get("database_specific", {}).get("severity", ""),
        "cvss": [s["score"] for s in vuln.get("severity", []) if s.get("score")],  # CVSS vectors
        "rev": osv_rev(vuln.get("modified", ""), pkgs),
        "updates": [{"date": date, "text": "published", "id": fp("osv", vid)}],
        "text": "",
    }
    if fixed:
        item["updates"].append({"date": (vuln.get("modified") or "")[:10],
                                "text": "fixed in " + ", ".join(fixed),
                                "id": fp("osv-fixed", vid, *fixed)})
    return item


def osv_get(api, vid):
    return json.loads(http_get(api + "vulns/" + urllib.parse.quote(vid, safe="")))


def fetch_osv(packages, known, api=OSV_API, osv_file=None):
    """Returns items and errors. An advisory whose "modified" did not change since it was marked is not
    downloaded again: it becomes a "cached" item with no updates, so only a new KEV status brings it back"""
    hits, full, errors = {}, {}, []  # id -> [modified, [packages]]; id -> advisory
    if osv_file:  # offline: a JSON list of {"package": {...}, "vuln": {...}}
        with open(osv_file) as f:
            for e in json.load(f):
                full[e["vuln"]["id"]] = e["vuln"]
                hits.setdefault(e["vuln"]["id"], [e["vuln"].get("modified", ""), []])[1].append(e["package"])
    queries = []
    for p in packages:
        q = {"package": {"ecosystem": p["ecosystem"], "name": p["name"]}}
        if p["version"]:
            q["version"] = p["version"]
        queries.append(q)
    todo, tokens = list(range(len(queries))) if not osv_file else [], {}
    for _ in range(10):  # a package without a version can have more than one page of results
        more = []
        for start in range(0, len(todo), 1000):
            chunk = todo[start:start + 1000]
            res = http_post_json(api + "querybatch",
                                 {"queries": [dict(queries[n], **({"page_token": tokens[n]} if n in tokens else {}))
                                              for n in chunk]})
            for n, r in zip(chunk, res.get("results", [])):
                for v in r.get("vulns") or []:
                    h = hits.setdefault(v["id"], [v.get("modified", ""), []])
                    if packages[n] not in h[1]:
                        h[1].append(packages[n])
                if r.get("next_page_token"):
                    tokens[n] = r["next_page_token"]
                    more.append(n)
        todo = more
        if not todo:
            break
    if todo:
        errors.append({"source": "osv", "error": f"{len(todo)} package(s) have more than 10 pages of results",
                       "partial": True})
    items = []
    for vid, (modified, pkgs) in hits.items():
        k = known.get(f"osv:{vid}")
        if vid not in full and k and modified and k.get("rev") == osv_rev(modified, pkgs):
            items.append({"key": f"osv:{vid}", "source": "osv", "title": k.get("title") or vid,
                          "link": f"https://osv.dev/vulnerability/{vid}", "date": "", "cves": k.get("cves", []),
                          "package": pkgs[0], "packages": pkgs, "updates": [], "cached": True})
            continue
        try:
            items.append(osv_item(full.get(vid) or osv_get(api, vid), pkgs))
        except Exception as e:  # one advisory that cannot be read must not hide the others
            errors.append({"source": "osv", "error": f"{vid}: {type(e).__name__}: {e}", "partial": True})
    return items, errors


# ---------- GHSA (GitHub Security Advisories) ----------

def read_ghsa(path):
    """One entry per line: owner/repo, repo|owner/repo, or ecosystem|name[|severity]"""
    out = []
    for line in data_lines(path):
        if "|" not in line and line.count("/") == 1:
            kind, target, sev = "repo", line, ""
        else:
            parts = [p.strip() for p in line.split("|")]
            kind = parts[0]
            target = parts[1] if len(parts) > 1 else ""
            sev = parts[2].lower() if len(parts) > 2 else ""
        if kind == "repo":
            owner, _, repo = target.partition("/")
            if not (owner and repo) or "/" in repo or any(c.isspace() for c in target) or ".." in (owner, repo):
                raise SystemExit(f"bad ghsa repo: {line!r} (expected owner/repo)")
            out.append(("repo", f"{owner}/{repo}", ""))
        elif kind == "ecosystem" and target and sev in ("", "low", "medium", "high", "critical"):
            out.append(("ecosystem", target, sev))
        else:
            raise SystemExit(f"bad ghsa line: {line!r} (expected owner/repo, repo|owner/repo, or ecosystem|name[|severity])")
    return out


def ghsa_headers():
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    auth = os.environ.get("GITHUB_TOKEN")
    if auth:
        headers["Authorization"] = f"Bearer {auth}"
    return headers


def ghsa_cvss(adv):
    vectors, score = [], None
    sevs = adv.get("cvss_severities") or {}
    for k in ("cvss_v4", "cvss_v3"):
        c = sevs.get(k) or {}
        if c.get("vector_string"):
            vectors.append(c["vector_string"])
        if c.get("score") is not None:
            score = max(score, float(c["score"])) if score is not None else float(c["score"])
    legacy = adv.get("cvss") or {}
    if legacy.get("vector_string") and legacy["vector_string"] not in vectors:
        vectors.append(legacy["vector_string"])
    if score is None and legacy.get("score") is not None:
        score = float(legacy["score"])
    return vectors, score


def ghsa_item(adv, sid):
    gid = adv.get("ghsa_id") or ""
    if not gid:
        return None
    cves = {adv["cve_id"]} if (adv.get("cve_id") or "").startswith("CVE-") else set()
    for ident in adv.get("identifiers") or []:
        val = ident.get("value") or ""
        if ident.get("type") == "CVE" and val.startswith("CVE-"):
            cves.add(val)
    fixed, pkgs = set(), []
    for v in adv.get("vulnerabilities") or []:
        fpv = v.get("first_patched_version")
        ver = fpv.get("identifier") if isinstance(fpv, dict) else fpv
        if isinstance(ver, str) and ver.strip():
            fixed.add(ver.strip())
        p = v.get("package") or {}
        if p.get("name"):
            pkgs.append({"ecosystem": p.get("ecosystem") or "", "name": p["name"],
                         "vulnerable_range": v.get("vulnerable_version_range") or ""})
    fixed_list = sorted(fixed)
    title = (adv.get("summary") or gid).strip()
    severity = (adv.get("severity") or "").lower()
    published = (adv.get("published_at") or adv.get("updated_at") or "")[:10]
    modified = (adv.get("updated_at") or "")[:10]
    vectors, score = ghsa_cvss(adv)
    updates = [{"date": published, "text": "published", "id": fp("ghsa", gid)}]
    if fixed_list:
        updates.append({"date": modified or published, "text": "fixed in " + ", ".join(fixed_list),
                        "id": fp("ghsa-fixed", gid, *fixed_list)})
    item = {
        "key": f"ghsa:{gid}",
        "source": sid,
        "title": title,
        "link": adv.get("html_url") or f"https://github.com/advisories/{gid}",
        "date": published,
        "summary": (adv.get("description") or "")[:1500],
        "cves": sorted(cves),
        "fixed_versions": fixed_list,
        "severity": severity,
        "cvss": vectors,
        "sig": fp(title, severity, *sorted(cves)),
        "updates": updates,
        "text": "",
    }
    if score is not None:
        item["cvss_score"] = score
    if pkgs:
        item["packages"] = pkgs
    return item


def fetch_ghsa_entry(kind, target, sev, api):
    if kind == "repo":
        owner, repo = target.split("/", 1)
        url = (f"{api}repos/{urllib.parse.quote(owner, safe='')}/"
               f"{urllib.parse.quote(repo, safe='')}/security-advisories?state=published&per_page=100")
        sid = f"ghsa:{target}"
    else:
        params = {"type": "reviewed", "ecosystem": target, "per_page": 100}
        if sev:
            params["severity"] = sev
        url = api + "advisories?" + urllib.parse.urlencode(params)
        sid = f"ghsa:ecosystem:{target}"
    raw = json.loads(http_get(url, extra_headers=ghsa_headers()))
    return sid, [i for i in (ghsa_item(adv, sid) for adv in raw) if i]


# ---------- NVD (CPE watch) ----------

def read_nvd(path):
    """One product per line: name|cpe:2.3:..."""
    out = []
    for line in data_lines(path):
        name, _, cpe = (p.strip() for p in line.partition("|"))
        if not (name and cpe.startswith("cpe:2.3:")):
            raise SystemExit(f"bad nvd line: {line!r} (expected name|cpe:2.3:...)")
        out.append((name, cpe))
    return out


def nvd_cvss(metrics):
    vectors, score, severity = [], None, ""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key) or []:
            d = m.get("cvssData") or {}
            if d.get("vectorString") and d["vectorString"] not in vectors:
                vectors.append(d["vectorString"])
            if score is None and d.get("baseScore") is not None:
                score = float(d["baseScore"])
                severity = d.get("baseSeverity") or m.get("baseSeverity") or ""
    return vectors, score, severity


def nvd_item(cve_obj, name):
    if cve_obj.get("vulnStatus") == "Rejected":
        return None
    cid = cve_obj.get("id") or ""
    if not cid:
        return None
    published = (cve_obj.get("published") or "")[:10]
    descs = cve_obj.get("descriptions") or []
    desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"),
                descs[0].get("value", "") if descs else "")
    vectors, score, severity = nvd_cvss(cve_obj.get("metrics") or {})
    item = {
        "key": f"nvd:{cid}",
        "source": f"nvd:{name}",
        "title": f"{name}: {cid}",
        "link": f"https://nvd.nist.gov/vuln/detail/{cid}",
        "date": published,
        "summary": desc[:1500],
        "cves": [cid],
        "product": name,
        "severity": severity,
        "cvss": vectors,
        "sig": fp(severity, str(score or "")),
        "updates": [{"date": published, "text": "published", "id": fp("nvd", cid)}],
        "text": "",
    }
    if score is not None:
        item["cvss_score"] = score
    return item


def nvd_window(today, nvd_days, since):
    today_d = datetime.date.fromisoformat(today)
    start_d = today_d - datetime.timedelta(days=min(max(nvd_days, 1), 119))
    if since:
        earliest = today_d - datetime.timedelta(days=119)
        since_d = datetime.date.fromisoformat(since)
        if since_d < start_d:
            start_d = max(since_d, earliest)
    return f"{start_d.isoformat()}T00:00:00.000Z", f"{today}T23:59:59.999Z"


# ---------- enrichment ----------

def add_kev_status(items, kev_items):
    """Mark items whose CVEs are in KEV, and add an update so a status change is shown again.
    kev_cves lists every CVE the item MENTIONS that is in KEV. A briefing can mention an older,
    exploited CVE as background: the reader of the output decides whether it is the item's own"""
    kev = {i["cves"][0]: i["kev"] for i in kev_items}
    for i in items:
        if i["source"] == "kev":
            continue
        hits = [c for c in i["cves"] if c in kev]
        if hits:
            i["kev_cves"] = {c: kev[c] for c in hits}
            for c in hits:
                i["updates"].append({"date": kev[c]["date_added"],
                                     "text": f"{c} added to CISA KEV (exploited in the wild)",
                                     "id": fp("kev", c)})


def add_epss(items):
    cves = sorted({c for i in items for c in i["cves"]})
    scores = {}
    for start in range(0, len(cves), 100):
        data = json.loads(http_get(EPSS_API + ",".join(cves[start:start + 100])))
        for row in data.get("data", []):
            scores[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
    for i in items:
        e = {c: scores[c] for c in i["cves"] if c in scores}
        if e:
            i["epss"] = e


def parse_cve_org(data):
    """Extract CVSS (from CNA or ADP) and affected version ranges from a CVE JSON 5.0 record"""
    containers = data.get("containers") or {}
    cna = containers.get("cna") or {}
    blocks = [cna] + [x for x in (containers.get("adp") or []) if isinstance(x, dict)]
    vectors, score, severity = [], None, ""
    for block in blocks:
        for m in block.get("metrics") or []:
            for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
                c = m.get(k) or {}
                if c.get("vectorString") and c["vectorString"] not in vectors:
                    vectors.append(c["vectorString"])
                if score is None and c.get("baseScore") is not None:
                    score = float(c["baseScore"])
                    severity = c.get("baseSeverity") or ""
    affected = []
    for a in cna.get("affected") or []:
        label = " / ".join(p for p in (a.get("vendor"), a.get("product"))
                           if p and p.lower() not in ("n/a", "unspecified"))
        parts = []
        for v in a.get("versions") or []:
            ver = v.get("version") or ""
            if v.get("status") == "unaffected" and a.get("defaultStatus") == "affected" and ver:
                parts.append(f"fixed >= {ver}")
                continue
            if v.get("status") not in ("affected", None):
                continue
            if v.get("lessThan"):
                parts.append(f"{ver} < {v['lessThan']}".strip())
            elif v.get("lessThanOrEqual"):
                parts.append(f"{ver} <= {v['lessThanOrEqual']}".strip())
            elif ver and ver.lower() not in ("n/a", "unspecified"):
                parts.append(ver)
        if label or parts:
            line = f"{label}: {', '.join(parts)}" if label and parts else (label or ", ".join(parts))
            if line not in affected:
                affected.append(line)
        if len(affected) >= 12:
            break
    out = {}
    if score is not None:
        out["score"] = score
    if severity:
        out["severity"] = severity
    if vectors:
        out["cvss"] = vectors
    if affected:
        out["affected"] = affected
    return out


def add_cve_details(items, api=CVE_ORG_API, max_cves=30):
    """Enrich items missing CVSS or affected versions via the public CVE.org JSON 5.0 API"""
    wanted, errors, details = [], [], {}
    for i in items:
        needs = (not i.get("cvss") and i.get("cvss_score") is None) or (not i.get("fixed_versions") and not i.get("affected"))
        if not needs:
            continue
        for c in i["cves"]:
            if c not in wanted:
                wanted.append(c)
    for cve in wanted[:max(max_cves, 0)]:
        try:
            info = parse_cve_org(json.loads(http_get(api + urllib.parse.quote(cve, safe=""))))
            if info:
                details[cve] = info
        except Exception as e:
            errors.append({"source": "cve_org", "error": f"{cve}: {type(e).__name__}: {e}", "partial": True})
    for i in items:
        d = {c: details[c] for c in i["cves"] if c in details}
        if d:
            i["cve_details"] = d
    return errors


# ---------- state ----------

def load_state(path):
    try:
        with open(path) as f:
            st = json.load(f)
    except FileNotFoundError:
        return None
    if st.get("version") == 2:  # vuln-digest prototype: {"slugs": {slug: {first_seen, updates}}}
        st = {"version": 3, "last_digest": st.get("last_digest"),
              "items": {f"zerowire:{k}": {"first_seen": v.get("first_seen"), "fp": v.get("updates", []),
                                          "last_shown": st.get("last_digest") or v.get("first_seen")}
                        for k, v in st.get("slugs", {}).items()}}
    if st.get("version") == 3:  # v4 adds "sources": the sources read in full, see baseline()
        src = {}
        for k in st["items"]:
            kind, _, rest = k.partition(":")
            src["feeds:" + rest.split(":", 1)[0] if kind == "feed" else kind] = st.get("last_digest") or "v3"
        st.update(version=4, sources=src)
    if st.get("version") != STATE_VERSION:
        raise SystemExit(f"{path}: unknown state version {st.get('version')!r}")
    st.setdefault("sources", {})
    return st


META = ("cves", "sig", "rev")  # kept in the state: CVEs for cross-source links, "sig" and "rev" to see changes


def prev_day(d):
    return (datetime.date.fromisoformat(d) - datetime.timedelta(days=1)).isoformat()


def baseline(st, items, done, today, since, failed=()):
    """Count old updates of a source as seen when it is read for the first time, so that a new feed,
    or a source that failed on the first run, does not flood the digest with its archive.
    The cut-off: --since if given; the first run's --since for a source that failed on that run;
    otherwise the day before the last digest. A source read only in part stays {"pending": cut-off}
    and keeps that cut-off until it is read in full. Returns True if the state changed"""
    src, changed = st["sources"], False
    for sid in failed:  # a feed that fails while its group is pending keeps the group's cut-off
        group = sid.split(":")[0]
        if group != sid and sid not in src and group in src and not isinstance(src[group], str):
            src[sid], changed = src[group] or {"pending": st.get("since") or today}, True
    for sid in sorted(done | {i["source"] for i in items}):
        if isinstance(src.get(sid), str):
            continue
        group = sid.split(":")[0]  # a pending "feeds" covers each feed of the list
        p = src.get(sid, src.get(group, "") if group != sid else "")
        if since:
            cutoff = since
        elif isinstance(p, dict):
            cutoff = p["pending"]
        elif p is None or not st.get("last_digest"):  # None: pending, from state v4 before 1.4.1
            cutoff = st.get("since") or today
        else:
            cutoff = prev_day(st["last_digest"])
        mark(st, [i for i in items if i["source"] == sid], today, only_before=cutoff)
        src[sid] = cutoff if sid in done else {"pending": cutoff}
        if sid in done and group != sid and not isinstance(src.get(group, ""), str):
            del src[group]
        changed = True
    return changed


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def mark(state, items, today, only_before=None):
    for i in items:
        # an update without a date is never older than the cut-off: it is shown once, not hidden for good
        ids = {u["id"] for u in i["updates"] if only_before is None or "" < u["date"] < only_before}
        if not ids:
            continue
        s = state["items"].setdefault(i["key"], {"first_seen": today, "fp": []})
        s["fp"] = sorted(set(s["fp"]) | ids)
        s.update({f: i[f] for f in META if i.get(f)})
        if only_before is None:  # delivered now: keep what the weekly summary and "I patched X" need
            last = max(i["updates"], key=lambda u: u["date"])
            s.update({"title": i.get("title"), "link": i.get("link"), "cves": i.get("cves", []),
                      "last_shown": today, "last_update": last["text"]})
        for c in i.get("kev_cves", {}):  # the KEV entry was shown inside this item
            if fp("kev", c) in ids:
                k = state["items"].setdefault(f"kev:{c}", {"first_seen": today, "fp": []})
                k["fp"] = sorted(set(k["fp"]) | {fp("kev", c)})
    return state


# ---------- main ----------

def collect(a, known):
    """Returns items, errors, the sources asked for, and the ids of the sources read in full"""
    sources = [s.strip() for s in a.sources.split(",") if s.strip()]
    items, errors, kev_items, done = [], [], [], set()
    for src in sources:
        try:
            if src == "zerowire":
                raw = open(a.zerowire_file, "rb").read() if a.zerowire_file else http_get(ZEROWIRE_FEED)
                warnings = []
                items += parse_zerowire(raw, warnings)
                errors += [{"source": src, "error": w, "partial": True} for w in warnings]
            elif src == "kev":
                raw = open(a.kev_file, "rb").read() if a.kev_file else http_get(KEV_JSON)
                kev_items = parse_kev(raw)
                items += kev_items
            elif src == "feeds":
                if not a.feeds:
                    raise ValueError("feeds needs --feeds FILE")
                for name, url in read_feeds(a.feeds):
                    try:
                        warnings = []
                        items += parse_vendor_feed(name, http_get(url), warnings)
                        errors += [{"source": f"feeds:{name}", "error": w, "partial": True} for w in warnings]
                        if not warnings:
                            done.add(f"feeds:{name}")
                    except Exception as e:
                        errors.append({"source": f"feeds:{name}", "error": f"{type(e).__name__}: {e}"})
            elif src == "osv":
                if not (a.packages or a.osv_file):
                    raise ValueError("osv needs --packages FILE")
                found, errs = fetch_osv(read_packages(a.packages) if a.packages else [], known, a.osv_api, a.osv_file)
                items += found
                errors += errs
            elif src == "ghsa":
                if not a.ghsa:
                    raise ValueError("ghsa needs --ghsa FILE")
                seen_ghsa = set()
                for kind, target, sev in read_ghsa(a.ghsa):
                    sid = f"ghsa:{target}" if kind == "repo" else f"ghsa:ecosystem:{target}"
                    try:
                        sid, found = fetch_ghsa_entry(kind, target, sev, a.ghsa_api)
                        for it in found:
                            if it["key"] not in seen_ghsa:
                                seen_ghsa.add(it["key"])
                                items.append(it)
                        done.add(sid)
                    except Exception as e:
                        errors.append({"source": sid, "error": f"{type(e).__name__}: {e}"})
            elif src == "nvd":
                if not a.nvd:
                    raise ValueError("nvd needs --nvd FILE")
                nvd_key = os.environ.get("NVD_API_KEY")
                headers = {"apiKey": nvd_key} if nvd_key else None
                delay = a.nvd_delay if a.nvd_delay is not None else (0.7 if nvd_key else 6.5)
                start_ts, end_ts = nvd_window(a.today, a.nvd_days, a.since)
                seen_nvd = {}
                for idx, (name, cpe) in enumerate(read_nvd(a.nvd)):
                    if idx and delay > 0:
                        time.sleep(delay)
                    sid = f"nvd:{name}"
                    try:
                        params = urllib.parse.urlencode({"virtualMatchString": cpe, "lastModStartDate": start_ts,
                                                         "lastModEndDate": end_ts, "resultsPerPage": 2000})
                        data = json.loads(http_get(f"{a.nvd_api}?{params}", extra_headers=headers))
                        vulns = data.get("vulnerabilities") or []
                        if (data.get("totalResults") or 0) > len(vulns):
                            errors.append({"source": sid, "error": f"{data['totalResults']} results, first {len(vulns)} read",
                                           "partial": True})
                        for v in vulns:
                            it = nvd_item(v.get("cve") or {}, name)
                            if not it:
                                continue
                            if it["key"] in seen_nvd:
                                seen_nvd[it["key"]].setdefault("products", [seen_nvd[it["key"]]["product"]]).append(name)
                            else:
                                seen_nvd[it["key"]] = it
                                items.append(it)
                        done.add(sid)
                    except Exception as e:
                        errors.append({"source": sid, "error": f"{type(e).__name__}: {e}"})
            else:
                raise ValueError(f"unknown source {src!r}")
            # osv counts as read once its queries answered: an advisory that failed comes later as new
            if src == "osv" or src not in ("feeds", "ghsa", "nvd") and not any(e["source"] == src for e in errors):
                done.add(src)
        except Exception as e:  # one source down must not hide the others
            errors.append({"source": src, "error": f"{type(e).__name__}: {e}"})
    if kev_items:
        add_kev_status(items, kev_items)
        # a KEV entry whose CVE is already part of another item is shown inside that item
        covered = {c for i in items if i["source"] != "kev" for c in i.get("kev_cves", {})}
        items = [i for i in items if not (i["source"] == "kev" and i["cves"][0] in covered)]
    return items, errors, sources, done


def link_same_cves(result, state_items):
    """One vulnerability often comes from several sources. Point at the other items, in this run and
    already delivered, so the digest can show it once"""
    by_cve, delivered = {}, {}
    for i in result:
        for c in i["cves"]:
            by_cve.setdefault(c, set()).add(i["key"])
    for k, v in state_items.items():
        if v.get("last_shown"):
            for c in v.get("cves") or []:
                delivered.setdefault(c, k)
    for i in result:
        same = sorted({k for c in i["cves"] for k in by_cve[c]} - {i["key"]})
        if same:
            i["same_cve_items"] = same
        earlier = {c: delivered[c] for c in i["cves"] if delivered.get(c, i["key"]) != i["key"]}
        if earlier:
            i["cves_delivered_in"] = earlier


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["fetch", "mark", "history", "check-feeds"])
    ap.add_argument("--days", type=int, default=28, help="history: items shown in the last N days (default 28)")
    ap.add_argument("--sources", default="zerowire,kev")
    ap.add_argument("--packages", help="file with ecosystem|name|version lines for OSV")
    ap.add_argument("--feeds", help="file with name|url lines: vendor RSS or Atom feeds for the feeds source")
    ap.add_argument("--ghsa", help="file with owner/repo or ecosystem|name[|severity] lines for GHSA")
    ap.add_argument("--nvd", help="file with name|cpe:2.3:... lines for NVD")
    ap.add_argument("--nvd-days", type=int, default=30, help="NVD modification window in days (1-120, default 30)")
    ap.add_argument("--epss", action="store_true", help="add EPSS scores to the result")
    ap.add_argument("--cve-details", action="store_true", help="enrich items missing CVSS/versions via CVE.org")
    ap.add_argument("--cve-details-max", type=int, default=30, help="max CVEs to enrich via CVE.org per run (default 30)")
    ap.add_argument("--kev-max-age", type=int, default=30,
                    help="show KEV entries added in the last N days only (default 30)")
    ap.add_argument("--since", metavar="YYYY-MM-DD",
                    help="first run without state: updates before this day count as seen. "
                         "With a state: the same, for sources read for the first time")
    ap.add_argument("--all", action="store_true", help="preview everything, state is not used")
    ap.add_argument("--state", default=os.path.join(HERE, "state.json"))
    ap.add_argument("--snapshot", default=os.path.join(HERE, "last_run.json"))
    ap.add_argument("--zerowire-file")
    ap.add_argument("--kev-file")
    ap.add_argument("--osv-file")
    ap.add_argument("--osv-api", default=OSV_API, help=argparse.SUPPRESS)
    ap.add_argument("--ghsa-api", default=GHSA_API, help=argparse.SUPPRESS)
    ap.add_argument("--nvd-api", default=NVD_API, help=argparse.SUPPRESS)
    ap.add_argument("--nvd-delay", type=float, default=None, help=argparse.SUPPRESS)
    ap.add_argument("--cve-api", default=CVE_ORG_API, help=argparse.SUPPRESS)
    ap.add_argument("--today", default=datetime.date.today().isoformat(), help=argparse.SUPPRESS)
    a = ap.parse_args()
    today = a.today

    if a.command == "mark":
        st = load_state(a.state) or {"version": STATE_VERSION, "items": {}, "sources": {}}
        try:
            with open(a.snapshot) as f:
                snap = json.load(f)
        except FileNotFoundError:
            raise SystemExit("no snapshot: run fetch first, deliver the digest, then mark")
        for i in snap["items"]:  # mark only the updates that were shown
            i["updates"] = i["new_updates"]
        mark(st, snap["items"], today)
        for k, meta in snap.get("meta", {}).items():  # what fetch learned about items it did not show
            if k in st["items"]:
                st["items"][k].update(meta)
        st["last_digest"] = snap["date"]
        save_json(a.state, st)
        os.remove(a.snapshot)
        print(f"marked {len(snap['items'])} item(s) as delivered", file=sys.stderr)
        return

    if a.command == "check-feeds":
        if not a.feeds:
            raise SystemExit("check-feeds needs --feeds FILE")
        json.dump([check_feed(n, u) for n, u in read_feeds(a.feeds)], sys.stdout, ensure_ascii=False, indent=1)
        print()
        return

    if a.command == "history":
        st = load_state(a.state)
        if st is None:
            raise SystemExit("state.json not found")
        cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=a.days)).isoformat()
        rows = [dict(key=k, **{f: v.get(f) for f in ("title", "link", "cves", "first_seen", "last_shown", "last_update")})
                for k, v in st["items"].items() if (v.get("last_shown") or "") >= cutoff]
        rows.sort(key=lambda r: r["last_shown"], reverse=True)
        json.dump(rows, sys.stdout, ensure_ascii=False, indent=1)
        print()
        return

    st = None if a.all else load_state(a.state)
    if st is None and not a.all and not a.since:
        raise SystemExit("state.json not found. Restore it from durable storage, or run again with "
                         "--since <date of the last digest> (for a first run: today minus the lookback)")
    items, errors, sources, done = collect(a, st["items"] if st else {})
    if "kev" in sources:  # the KEV catalog holds 1000+ entries; only recent ones are news
        cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=a.kev_max_age)).isoformat()
        items = [i for i in items if i["source"] != "kev" or i["date"] >= cutoff]

    if not a.all:
        first = st is None
        if first:  # a source that failed now is pending: it gets the same cut-off when it answers
            st = {"version": STATE_VERSION, "items": {}, "last_digest": None, "since": a.since,
                  "sources": {e["source"]: {"pending": a.since} for e in errors}}
        if baseline(st, items, done, today, a.since, {e["source"] for e in errors}) or first:
            save_json(a.state, st)

    result, meta = [], {}
    for i in items:
        known = None if a.all else st["items"].get(i["key"])
        if known is None:
            i["status"], i["new_updates"] = "new", i["updates"]
        else:
            if i.get("sig") and known.get("sig") and known["sig"] != i["sig"]:
                added = sorted(set(i["cves"]) - set(known.get("cves") or []))
                i["updates"].append({"date": i["date"] or today, "id": fp("changed", i["key"], i["sig"]),
                                     "text": "advisory changed" + (": adds " + ", ".join(added) if added else "")})
            meta[i["key"]] = {f: i[f] for f in META if i.get(f) and i[f] != known.get(f)}
            seen = set(known["fp"])
            fresh = [u for u in i["updates"] if u["id"] not in seen and u.get("legacy") not in seen]
            if not fresh:
                continue
            if i.pop("cached", False):  # an advisory that was not downloaded: get it now to show it
                try:
                    full = osv_item(osv_get(a.osv_api, i["key"][4:]), i["packages"])
                except Exception as e:
                    errors.append({"source": "osv", "error": f"{i['key']}: {type(e).__name__}: {e}"})
                    continue
                full["updates"] += i["updates"]
                full.update({k: v for k, v in i.items() if k == "kev_cves"})
                i = full
            # "updated" only for an item the user has seen; one known only from a --since rebuild is new to them
            i["status"] = "updated" if known.get("last_shown") else "new"
            i["new_updates"] = fresh
        result.append(i)
    link_same_cves(result, {} if a.all else st["items"])

    if a.epss and result:
        try:
            add_epss(result)
        except Exception as e:
            errors.append({"source": "epss", "error": f"{type(e).__name__}: {e}"})

    if a.cve_details and result:
        errors += add_cve_details(result, a.cve_api, a.cve_details_max)

    result.sort(key=lambda i: max([u["date"] for u in i["new_updates"]] or [i["date"]]), reverse=True)
    out = {"generated": today, "tool_version": VERSION, "sources": sources,
           "last_digest": None if a.all else st.get("last_digest"),
           "errors": errors, "items": result}
    if not a.all:
        save_json(a.snapshot, {"date": today, "items": result, "meta": {k: v for k, v in meta.items() if v}})
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main()
