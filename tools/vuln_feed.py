#!/usr/bin/env python3
"""vuln_feed.py - collect new and updated vulnerability items for a digest, without repeats.

Part of vuln-digest: https://vuln-digest.secmy.app/
Python 3.9+, standard library only. Read this file before you run it.

Sources:
  zerowire  Cloudflare Radar Zero Wire briefings (RSS)
  kev       CISA Known Exploited Vulnerabilities catalog (JSON)
  osv       OSV.dev advisories for the packages listed in --packages

How repeats are avoided:
  every item has a key (zerowire:<slug>, kev:<CVE>, osv:<ID>) and a list of
  fingerprints of its updates. An item is shown when its key is new, or when it
  has a fingerprint that was not shown before. A guid or a "last reviewed" date
  that changes alone does not make an update. When a CVE of a known item enters
  the KEV catalog, the item gets a new update "added to CISA KEV"

Usage:
  python3 -I vuln_feed.py fetch [--sources zerowire,kev] [--packages FILE] [--epss]
      print new and updated items as JSON and save them to the snapshot file
  python3 -I vuln_feed.py mark
      mark exactly the items of the snapshot as delivered. Does not fetch again.
      Run it only after the digest was delivered
  python3 -I vuln_feed.py fetch --since YYYY-MM-DD
      no state file yet: treat every update dated before this day as already seen
  python3 -I vuln_feed.py fetch --all
      everything the sources hold now, state is not read or changed (preview)
  python3 -I vuln_feed.py history [--days 28]
      items delivered in the last N days, newest first: for the weekly summary
      and for "I patched X" feedback

Files (next to this script unless set): state.json, last_run.json
Offline testing: --zerowire-file, --kev-file, --osv-file read local copies
"""
import argparse
import datetime
import hashlib
import html
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

VERSION = "1.0.0"
UA = f"vuln-digest/{VERSION} (+https://vuln-digest.secmy.app/)"
ZEROWIRE_FEED = "https://radar.cloudflare.com/zero-wire/feed"
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
EPSS_API = "https://api.first.org/data/v1/epss?cve="
NS = {"content": "http://purl.org/rss/1.0/modules/content/"}
HERE = os.path.dirname(os.path.abspath(__file__))
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
STATE_VERSION = 3


def fp(*parts):
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:16]


def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def http_post_json(url, obj, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST",
                                 headers={"User-Agent": UA, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


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


def parse_zerowire(raw):
    root = ET.fromstring(raw)
    items = []
    for it in root.iter("item"):
        guid = it.findtext("guid") or it.findtext("link") or ""
        desc = it.findtext("description") or ""
        content = it.findtext("content:encoded", namespaces=NS) or ""
        pd = it.findtext("pubDate")
        date = parsedate_to_datetime(pd).date().isoformat() if pd else ""
        slug = guid.split("@")[0].rstrip("/").split("/")[-1]
        updates = zerowire_updates(content)
        if not updates:  # "legacy": the prototype fingerprinted such items by guid
            updates = [{"date": date, "text": "published", "id": fp("published", slug),
                        "legacy": hashlib.sha1(guid.encode()).hexdigest()[:16]}]
        items.append({
            "key": f"zerowire:{slug}",
            "source": "zerowire",
            "title": it.findtext("title"),
            "link": it.findtext("link"),
            "date": date,
            "summary": strip_html(desc),
            "cves": sorted(set(CVE_RE.findall(content + desc))),
            "updates": updates,
            "text": strip_html(content)[:8000],
        })
    return items


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
    """One package per line: ecosystem|name|version  (version may be empty). # starts a comment"""
    out = []
    with open(path) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 2:
                raise SystemExit(f"bad package line: {line!r} (expected ecosystem|name|version)")
            out.append({"ecosystem": parts[0], "name": parts[1],
                        "version": parts[2] if len(parts) > 2 else ""})
    return out


def osv_fixed(vuln):
    fixed = set()
    for a in vuln.get("affected", []):
        for r in a.get("ranges", []):
            for e in r.get("events", []):
                if "fixed" in e:
                    fixed.add(e["fixed"])
    return sorted(fixed)


def osv_item(vuln, pkg):
    vid = vuln.get("id", "")
    aliases = vuln.get("aliases", [])
    date = (vuln.get("published") or vuln.get("modified") or "")[:10]
    fixed = osv_fixed(vuln)
    item = {
        "key": f"osv:{vid}",
        "source": "osv",
        "title": vuln.get("summary") or vid,
        "link": f"https://osv.dev/vulnerability/{vid}",
        "date": date,
        "summary": (vuln.get("details") or "")[:1500],
        "cves": sorted(a for a in aliases if a.startswith("CVE-")),
        "package": pkg,
        "fixed_versions": fixed,
        "severity": vuln.get("database_specific", {}).get("severity", ""),
        "updates": [{"date": date, "text": "published", "id": fp("osv", vid)}],
        "text": "",
    }
    if fixed:
        item["updates"].append({"date": (vuln.get("modified") or "")[:10],
                                "text": "fixed in " + ", ".join(fixed),
                                "id": fp("osv-fixed", vid, *fixed)})
    return item


def fetch_osv(packages, osv_file=None):
    if osv_file:  # offline: a JSON list of {"package": {...}, "vuln": {...}}
        with open(osv_file) as f:
            return [osv_item(e["vuln"], e["package"]) for e in json.load(f)]
    queries = []
    for p in packages:
        q = {"package": {"ecosystem": p["ecosystem"], "name": p["name"]}}
        if p["version"]:
            q["version"] = p["version"]
        queries.append(q)
    items, seen = [], set()
    for start in range(0, len(queries), 1000):
        chunk = queries[start:start + 1000]
        res = http_post_json(OSV_BATCH, {"queries": chunk})
        for pkg, r in zip(packages[start:start + 1000], res.get("results", [])):
            for v in r.get("vulns", []) or []:
                if v["id"] in seen:
                    continue
                seen.add(v["id"])
                items.append(osv_item(json.loads(http_get(OSV_VULN + v["id"])), pkg))
    return items


# ---------- enrichment ----------

def add_kev_status(items, kev_items):
    """Mark items whose CVEs are in KEV, and add an update so a status change is shown again"""
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


# ---------- state ----------

def load_state(path):
    try:
        with open(path) as f:
            st = json.load(f)
    except FileNotFoundError:
        return None
    if st.get("version") == 2:  # vuln-digest prototype: {"slugs": {slug: {first_seen, updates}}}
        st = {"version": STATE_VERSION, "last_digest": st.get("last_digest"),
              "items": {f"zerowire:{k}": {"first_seen": v.get("first_seen"), "fp": v.get("updates", [])}
                        for k, v in st.get("slugs", {}).items()}}
    if st.get("version") != STATE_VERSION:
        raise SystemExit(f"{path}: unknown state version {st.get('version')!r}")
    return st


def save_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def mark(state, items, today, only_before=None):
    for i in items:
        ids = {u["id"] for u in i["updates"] if only_before is None or u["date"] < only_before}
        if not ids:
            continue
        s = state["items"].setdefault(i["key"], {"first_seen": today, "fp": []})
        s["fp"] = sorted(set(s["fp"]) | ids)
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

def collect(a):
    sources = [s.strip() for s in a.sources.split(",") if s.strip()]
    items, errors, kev_items = [], [], []
    for src in sources:
        try:
            if src == "zerowire":
                raw = open(a.zerowire_file, "rb").read() if a.zerowire_file else http_get(ZEROWIRE_FEED)
                items += parse_zerowire(raw)
            elif src == "kev":
                raw = open(a.kev_file, "rb").read() if a.kev_file else http_get(KEV_JSON)
                kev_items = parse_kev(raw)
                items += kev_items
            elif src == "osv":
                if not (a.packages or a.osv_file):
                    raise ValueError("osv needs --packages FILE")
                items += fetch_osv(read_packages(a.packages) if a.packages else [], a.osv_file)
            else:
                raise ValueError(f"unknown source {src!r}")
        except Exception as e:  # one source down must not hide the others
            errors.append({"source": src, "error": f"{type(e).__name__}: {e}"})
    if kev_items:
        add_kev_status(items, kev_items)
        # a KEV entry whose CVE is already part of another item is shown inside that item
        covered = {c for i in items if i["source"] != "kev" for c in i.get("kev_cves", {})}
        items = [i for i in items if not (i["source"] == "kev" and i["cves"][0] in covered)]
    return items, errors, sources


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["fetch", "mark", "history"])
    ap.add_argument("--days", type=int, default=28, help="history: items shown in the last N days (default 28)")
    ap.add_argument("--sources", default="zerowire,kev")
    ap.add_argument("--packages", help="file with ecosystem|name|version lines for OSV")
    ap.add_argument("--epss", action="store_true", help="add EPSS scores to the result")
    ap.add_argument("--kev-max-age", type=int, default=30,
                    help="show KEV entries added in the last N days only (default 30)")
    ap.add_argument("--since", metavar="YYYY-MM-DD", help="first run without state: updates before this day count as seen")
    ap.add_argument("--all", action="store_true", help="preview everything, state is not used")
    ap.add_argument("--state", default=os.path.join(HERE, "state.json"))
    ap.add_argument("--snapshot", default=os.path.join(HERE, "last_run.json"))
    ap.add_argument("--zerowire-file")
    ap.add_argument("--kev-file")
    ap.add_argument("--osv-file")
    ap.add_argument("--today", default=datetime.date.today().isoformat(), help=argparse.SUPPRESS)
    a = ap.parse_args()
    today = a.today

    if a.command == "mark":
        st = load_state(a.state) or {"version": STATE_VERSION, "items": {}}
        try:
            with open(a.snapshot) as f:
                snap = json.load(f)
        except FileNotFoundError:
            raise SystemExit("no snapshot: run fetch first, deliver the digest, then mark")
        for i in snap["items"]:  # mark only the updates that were shown
            i["updates"] = i["new_updates"]
        mark(st, snap["items"], today)
        st["last_digest"] = snap["date"]
        save_json(a.state, st)
        os.remove(a.snapshot)
        print(f"marked {len(snap['items'])} item(s) as delivered", file=sys.stderr)
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

    items, errors, sources = collect(a)
    if "kev" in sources:  # the KEV catalog holds 1000+ entries; only recent ones are news
        cutoff = (datetime.date.fromisoformat(today) - datetime.timedelta(days=a.kev_max_age)).isoformat()
        items = [i for i in items if i["source"] != "kev" or i["date"] >= cutoff]

    st = None if a.all else load_state(a.state)
    if st is None and not a.all:
        if not a.since:
            raise SystemExit("state.json not found. Restore it from durable storage, or run again with "
                             "--since <date of the last digest> (for a first run: today minus the lookback)")
        st = {"version": STATE_VERSION, "items": {}, "last_digest": None}
        mark(st, items, today, only_before=a.since)
        save_json(a.state, st)

    result = []
    for i in items:
        known = None if a.all else st["items"].get(i["key"])
        if known is None:
            i["status"], i["new_updates"] = "new", i["updates"]
        else:
            seen = set(known["fp"])
            fresh = [u for u in i["updates"] if u["id"] not in seen and u.get("legacy") not in seen]
            if not fresh:
                continue
            i["status"], i["new_updates"] = "updated", fresh
        result.append(i)

    if a.epss and result:
        try:
            add_epss(result)
        except Exception as e:
            errors.append({"source": "epss", "error": f"{type(e).__name__}: {e}"})

    result.sort(key=lambda i: max([u["date"] for u in i["new_updates"]] or [i["date"]]), reverse=True)
    out = {"generated": today, "tool_version": VERSION, "sources": sources,
           "last_digest": None if a.all else st.get("last_digest"),
           "errors": errors, "items": result}
    if not a.all:
        save_json(a.snapshot, {"date": today, "items": result})
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main()
