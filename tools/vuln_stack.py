#!/usr/bin/env python3
"""vuln_stack.py - extract packages, runtimes and source candidates for vuln-digest setup and rescan.

Part of vuln-digest: https://vuln-digest.secmy.app/
Python 3.9+, standard library only. Read this file before you run it.

Commands:
  python3 -I vuln_stack.py scan <dir-or-file> [--out packages.txt] [--dev-out packages-dev.txt]
      [--diff existing-packages.txt] [--allow-scope @scope] [--exclude-prefix prefix]
      parse lock files, SBOMs (CycloneDX, SPDX) and runtime files; fail-closed on suspect scopes
  python3 -I vuln_stack.py scan --stdin --format package-lock.json [--diff existing-packages.txt]
      parse a single file passed on stdin (for repositories read via a connector without cloning)
  python3 -I vuln_stack.py suggest-sources --stack nginx,kubernetes,fortigate [--catalog catalog.json]
      match stack products against the curated source catalog (feeds, GHSA repos, NVD CPEs)
  python3 -I vuln_stack.py discover-feeds <url>
      find RSS/Atom feed links and GitHub Security Advisories links on a vendor security page
  python3 -I vuln_stack.py find-cpe <query> [--max 10]
      search the NVD CPE 2.0 API and return grouped cpe:2.3 prefixes (optional NVD_API_KEY env)
"""
import argparse
import html.parser
import json
import os
import re
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

VERSION = "1.6.1"
UA = f"vuln-digest/{VERSION} (+https://vuln-digest.secmy.app/)"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CATALOG = os.path.join(HERE, "catalog.json")
NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
MAX_BYTES = 16 * 1024 * 1024  # a larger page or API response is refused
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "vendor", "dist", "build",
    "target", "__pycache__", ".next", ".nuxt", ".tox", ".mypy_cache", ".pytest_cache",
}
UNSUPPORTED_LOCKFILES = {"pnpm-lock.yaml", "yarn.lock", "gradle.lockfile", "pubspec.lock"}
PUBLIC_GO_HOSTS = {
    "github.com", "golang.org", "gopkg.in", "google.golang.org", "k8s.io", "sigs.k8s.io",
    "go.uber.org", "go.opentelemetry.io", "cloud.google.com", "go.etcd.io", "gocloud.dev",
    "honnef.co", "gorm.io", "nhooyr.io", "modernc.org", "dario.cat", "cel.dev", "filippo.io",
}
PURL_ECOSYSTEMS = {
    "npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "nuget": "NuGet",
    "cargo": "crates.io", "gem": "RubyGems", "composer": "Packagist", "deb": "Debian",
    "apk": "Alpine", "rpm": "rpm", "pub": "Pub", "swift": "SwiftURL", "githubactions": "GitHub Actions",
}
# pkg:rpm/<vendor>/...: the vendor picks the OSV ecosystem; an unknown vendor is dropped, not guessed
RPM_VENDORS = {
    "redhat": "Red Hat", "rhel": "Red Hat", "rocky": "Rocky Linux", "rockylinux": "Rocky Linux",
    "almalinux": "AlmaLinux", "suse": "SUSE", "sles": "SUSE", "opensuse": "openSUSE", "mageia": "Mageia",
}


def web_url(url):
    """Only http and https go to urlopen. Other schemes, such as file: or ftp:, are refused"""
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"not an http(s) URL: {url!r}")
    return url


def token_ok(url):
    """An API key goes only over https, or to this machine (the tests)"""
    u = urllib.parse.urlsplit(url)
    return u.scheme == "https" or u.hostname in ("127.0.0.1", "localhost")


def same_origin(a, b):
    u1, u2 = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    return (u1.scheme, u1.hostname, u1.port) == (u2.scheme, u2.hostname, u2.port)


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is followed only to http or https, and never carries tokens to another origin"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        web_url(newurl)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and (not same_origin(req.full_url, newurl) or not token_ok(newurl)):
            for h in [k for k in new.headers if k.lower() in ("authorization", "apikey")]:
                del new.headers[h]
        return new


OPENER = urllib.request.build_opener(SafeRedirect)


# S310: urlopen gets only URLs that web_url() checked
def http_get(url, timeout=30, extra_headers=None):
    headers = {"User-Agent": UA}
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(web_url(url), headers=headers)  # noqa: S310
    with OPENER.open(req, timeout=timeout) as r:
        body = r.read(MAX_BYTES + 1)
    if len(body) > MAX_BYTES:
        raise ValueError(f"response larger than {MAX_BYTES} bytes: {url}")
    return body


def strip_v(ver):
    return ver[1:] if re.match(r"^v\d", ver or "") else (ver or "")


# ---------- SBOM & lock file parsers ----------

def parse_purl(purl):
    """Parse a Package URL (pkg:type/namespace/name@version) into (ecosystem, name, version)"""
    if not (purl or "").startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    ptype, _, rest = body.partition("/")
    eco = PURL_ECOSYSTEMS.get(ptype.lower())
    if not eco or not rest:
        return None
    path_part, _, ver = rest.partition("@")
    ver = urllib.parse.unquote(ver).strip()
    parts = [urllib.parse.unquote(p) for p in path_part.split("/") if p]
    if not parts:
        return None
    if eco == "rpm":
        eco = RPM_VENDORS.get(parts[0].lower()) if len(parts) >= 2 else None
        if not eco:
            return None
        return eco, parts[-1], ver
    if eco == "Maven" and len(parts) >= 2:
        name = f"{parts[0]}:{parts[1]}"
    elif eco in ("Debian", "Alpine") and len(parts) >= 2:
        if eco == "Debian" and parts[0].lower() == "ubuntu":
            eco = "Ubuntu"
        name = parts[-1]
    else:
        name = "/".join(parts)
    if eco == "Go":
        ver = strip_v(ver)
    return eco, name, ver


def parse_npm_lock(data):
    """package-lock.json v1, v2 and v3"""
    out = []
    if "packages" in data and isinstance(data["packages"], dict):
        for path, meta in data["packages"].items():
            if not path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            ver = meta.get("version") or ""
            resolved = meta.get("resolved") or ""
            if "node_modules/" not in path or meta.get("link") or (
                    resolved and urllib.parse.urlsplit(resolved).hostname != "registry.npmjs.org"):
                out.append(("npm", name, ver, "private"))
            elif meta.get("dev") or meta.get("devOptional"):
                out.append(("npm", name, ver, "dev"))
            elif ver:
                out.append(("npm", name, ver, "prod"))
        return out

    def walk_v1(deps):
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = meta.get("version") or ""
            resolved = meta.get("resolved") or ""
            if resolved and urllib.parse.urlsplit(resolved).hostname != "registry.npmjs.org":
                out.append(("npm", name, ver, "private"))
            elif meta.get("dev"):
                out.append(("npm", name, ver, "dev"))
            elif ver and not ver.startswith(("file:", "git+", "http://", "https://")):
                out.append(("npm", name, ver, "prod"))
            elif ver:
                out.append(("npm", name, ver, "private"))
            walk_v1(meta.get("dependencies"))

    walk_v1(data.get("dependencies"))
    return out


def parse_composer_lock(data):
    out = []
    for key, role in (("packages", "prod"), ("packages-dev", "dev")):
        for pkg in data.get(key) or []:
            name, ver = pkg.get("name") or "", strip_v(pkg.get("version") or "")
            if not name:
                continue
            dist_type = (pkg.get("dist") or {}).get("type", "")
            src_type = (pkg.get("source") or {}).get("type", "")
            if dist_type == "path" or src_type == "path":
                out.append(("Packagist", name, ver, "private"))
            elif ver:
                out.append(("Packagist", name, ver, role))
    return out


def parse_nuget_lock(data):
    out = []
    for deps in (data.get("dependencies") or {}).values():
        if not isinstance(deps, dict):
            continue
        for name, meta in deps.items():
            ver = (meta or {}).get("resolved") or ""
            if ver:
                out.append(("NuGet", name, ver, "prod"))
    return out


def parse_pipfile_lock(data):
    out = []
    for section, role in (("default", "prod"), ("develop", "dev")):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            if meta.get("path") or meta.get("git") or meta.get("file"):
                out.append(("PyPI", name, "", "private"))
                continue
            ver = (meta.get("version") or "").lstrip("=")
            if ver:
                out.append(("PyPI", name, ver, role))
    return out


def parse_cdx(data):
    out = []
    for c in data.get("components") or []:
        parsed = parse_purl(c.get("purl"))
        if parsed:
            out.append((*parsed, "prod"))
    return out


def parse_spdx(data):
    out = []
    for p in data.get("packages") or []:
        for ref in p.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                parsed = parse_purl(ref.get("referenceLocator"))
                if parsed:
                    out.append((*parsed, "prod"))
                    break
    return out


def toml_blocks(text):
    """Minimal reader for [[package]] blocks in Cargo.lock, poetry.lock and uv.lock (Python 3.9+ stdlib)"""
    blocks = []
    cur, section = None, ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line == "[[package]]":
            if cur:
                blocks.append(cur)
            cur, section = {}, ""
            continue
        if cur is None:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            key = f"{section}.{k.strip()}" if section else k.strip()
            v = v.strip()
            q = re.match(r"^(\"[^\"]*\"|'[^']*')", v)
            # a '#' inside quotes is data (Cargo git sources end in #<commit>); after them it is a comment
            cur[key] = q.group(1) if q else v.split("#", 1)[0].strip()
    if cur:
        blocks.append(cur)
    return blocks


def unquote(s):
    s = (s or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def parse_cargo_lock(text):
    out = []
    for b in toml_blocks(text):
        name, ver = unquote(b.get("name")), unquote(b.get("version"))
        if not (name and ver):
            continue
        src = unquote(b.get("source"))
        if not src or "crates.io-index" not in src:
            out.append(("crates.io", name, ver, "private"))
        else:
            out.append(("crates.io", name, ver, "prod"))
    return out


def parse_poetry_lock(text):
    out = []
    for b in toml_blocks(text):
        name, ver = unquote(b.get("name")), unquote(b.get("version"))
        if not (name and ver):
            continue
        src_type = unquote(b.get("package.source.type"))
        if src_type in ("directory", "file", "url", "git"):
            out.append(("PyPI", name, ver, "private"))
            continue
        cat = unquote(b.get("category")).lower()
        groups = re.findall(r'"([^"]+)"|\'([^\']+)\'', b.get("groups", ""))
        gnames = {a or b_ for a, b_ in groups}
        if cat == "dev" or (gnames and gnames <= {"dev", "test", "lint", "docs"}):
            out.append(("PyPI", name, ver, "dev"))
        else:
            out.append(("PyPI", name, ver, "prod"))
    return out


def parse_uv_lock(text):
    out = []
    for b in toml_blocks(text):
        name, ver = unquote(b.get("name")), unquote(b.get("version"))
        if not (name and ver):
            continue
        src = b.get("source", "")
        if any(k in src for k in ("virtual", "editable", "directory", "path", "git")):
            out.append(("PyPI", name, ver, "private"))
        elif "registry" in src and "pypi.org" not in src:
            out.append(("PyPI", name, ver, "private"))
        else:
            out.append(("PyPI", name, ver, "prod"))
    return out


def parse_go_mod(text):
    """Returns (packages, own_modules, runtimes, local_replaces).
    Since Go 1.17 the require lines list every module of the build, direct and // indirect,
    at the version the build selects, so they are the package list; go.sum is not"""
    raw_reqs, own, runtimes, replaces, remote_rep = [], set(), [], set(), {}
    in_require = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if in_require:
            if line == ")":
                in_require = False
            elif len(line.split()) >= 2:
                mod, ver = line.split()[:2]
                raw_reqs.append((mod.strip('"'), strip_v(ver)))
            continue
        if re.match(r"^require\s*\($", line):
            in_require = True
            continue
        q = re.match(r"^require\s+(\S+)\s+(\S+)", line)
        if q:
            raw_reqs.append((q.group(1).strip('"'), strip_v(q.group(2))))
            continue
        m = re.match(r"^module\s+(\S+)", line)
        if m:
            own.add(m.group(1).strip('"'))
            continue
        g = re.match(r"^go\s+(\d+\.\d+(?:\.\d+)?)", line)
        if g:
            runtimes.append({"name": "go", "version": g.group(1)})
            continue
        if "=>" in line:
            left, _, right = re.sub(r"^replace\s+", "", line).partition("=>")
            lp, rp = left.split(), right.split()
            if not (lp and rp):
                continue
            old_m = lp[0].strip('"')
            old_v = strip_v(lp[1]) if len(lp) >= 2 else None
            target = rp[0].strip('"')
            if len(rp) >= 2 and not target.startswith((".", "/")) and "." in target.split("/")[0]:
                remote_rep[(old_m, old_v)] = (target, strip_v(rp[1]))
                if old_m != target:
                    replaces.add(old_m)
            else:
                replaces.add(old_m)
    pkgs = []
    for mod, ver in raw_reqs:
        if (mod, ver) in remote_rep:
            mod, ver = remote_rep[(mod, ver)]
        elif (mod, None) in remote_rep:
            mod, ver = remote_rep[(mod, None)]
        pkgs.append(("Go", mod, ver, "prod"))
    return pkgs, own, runtimes, replaces


def go_mod_lists_all(path):
    """True when go.mod says go 1.17 or later: then its require lines hold the whole build list"""
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            m = re.search(r"(?m)^go\s+(\d+)\.(\d+)", f.read(MAX_BYTES))
    except OSError:
        return False
    return bool(m) and (int(m.group(1)), int(m.group(2))) >= (1, 17)


def go_ver_key(ver):
    """Sort key for Go module versions: release > its pre-release, numbers compared as numbers"""
    core, _, pre = strip_v(ver).split("+", 1)[0].partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in core.split("."))
    return nums, pre == "", pre


def parse_go_sum(text):
    """Fallback when there is no go.mod next to it. go.sum keeps every version that was
    ever in the module graph, so only the highest one per module is taken"""
    best = {}
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        mod, ver = parts[0], strip_v(parts[1].split("/go.mod", 1)[0])
        if mod not in best or go_ver_key(ver) > go_ver_key(best[mod]):
            best[mod] = ver
    return [("Go", mod, ver, "prod") for mod, ver in best.items()]


def parse_requirements(filename, text):
    is_dev = any(tok in filename.lower() for tok in ("dev", "test", "lint", "doc"))
    role = "dev" if is_dev else "prod"
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "--", "-c", "-f", "-i")):
            continue
        if line.startswith("-e") or "git+" in line or "://" in line:
            out.append(("PyPI", line, "", "private"))
            continue
        line = line.split(";", 1)[0].strip()
        m = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9_.+-]+)", line)
        if m:
            out.append(("PyPI", m.group(1), m.group(2), role))
    return out


def parse_gemfile_lock(text):
    out = []
    section, remote, in_specs = "", "", False
    for raw in text.splitlines():
        if not raw.strip():
            in_specs = False
            continue
        if not raw.startswith(" "):
            section, remote, in_specs = raw.strip(), "", False
            continue
        stripped = raw.strip()
        if stripped.startswith("remote:"):
            remote = stripped.split(":", 1)[1].strip()
            continue
        if stripped == "specs:":
            in_specs = True
            continue
        if in_specs and raw.startswith("    ") and not raw.startswith("      "):
            m = re.match(r"^([A-Za-z0-9_.-]+)\s+\(([^)]+)\)", stripped)
            if m:
                is_pub = section == "GEM" and "rubygems.org" in remote
                out.append(("RubyGems", m.group(1), m.group(2), "prod" if is_pub else "private"))
    return out


def lname(el):
    return el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else ""


# S314: xml.etree does not load external entities or DTDs, and expat 2.4.1+ limits entity expansion
def parse_pom_xml(text):
    out = []
    try:
        root = ET.fromstring(text)  # noqa: S314
    except ET.ParseError:
        return out
    for dep in root.iter():
        if lname(dep) != "dependency":
            continue
        fields = {lname(c): (c.text or "").strip() for c in dep}
        gid, aid, ver = fields.get("groupId", ""), fields.get("artifactId", ""), fields.get("version", "")
        if not (gid and aid and ver) or "${" in ver:
            continue
        role = "dev" if fields.get("scope", "").lower() in ("test", "provided") else "prod"
        out.append(("Maven", f"{gid}:{aid}", ver, role))
    return out


def parse_dotnet_xml(text):
    out = []
    try:
        root = ET.fromstring(text)  # noqa: S314 - safe for the same reason as in parse_pom_xml
    except ET.ParseError:
        return out
    for el in root.iter():
        if lname(el) in ("PackageReference", "PackageVersion"):
            name = (el.get("Include") or el.get("Update") or "").strip()
            ver = (el.get("Version") or "").strip()
            if name and ver and not ver.startswith("$("):
                out.append(("NuGet", name, ver, "prod"))
    return out


# ---------- Runtimes & Dockerfiles ----------

def parse_dockerfile(text):
    runtimes, stages = [], set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not m:
            continue
        img, stage = m.group(1), m.group(2)
        if stage:
            stages.add(stage.lower())
        img = img.split("@", 1)[0]
        if img.lower() == "scratch" or img.lower() in stages or "$" in img:
            continue
        name, _, tag = img.rpartition(":") if ":" in img.split("/")[-1] else (img, "", "")
        short = name.rsplit("/", 1)[-1]
        runtimes.append({"name": short, "version": tag or "latest"})
    return runtimes


def parse_runtime_file(filename, text):
    base = os.path.basename(filename)
    if base == "Dockerfile" or base.startswith("Dockerfile."):
        return parse_dockerfile(text)
    if base == ".nvmrc":
        ver = strip_v(text.strip().splitlines()[0].strip()) if text.strip() else ""
        return [{"name": "node", "version": ver}] if ver else []
    if base == ".python-version":
        ver = text.strip().splitlines()[0].strip() if text.strip() else ""
        return [{"name": "python", "version": ver}] if ver else []
    if base == ".tool-versions":
        out = []
        for raw in text.splitlines():
            parts = raw.split("#", 1)[0].split()
            if len(parts) >= 2:
                out.append({"name": parts[0], "version": parts[1]})
        return out
    if base == "global.json":
        try:
            ver = (json.loads(text).get("sdk") or {}).get("version") or ""
            return [{"name": ".net", "version": ver}] if ver else []
        except json.JSONDecodeError:
            return []
    return []


# ---------- Scanning, privacy classification & diff ----------

def parse_one(relpath, text):
    """Returns (packages, runtimes, own_go_modules, unsupported_reason)"""
    base = os.path.basename(relpath)
    if base in UNSUPPORTED_LOCKFILES:
        return [], [], set(), "convert to CycloneDX/SPDX SBOM or inspect directly"
    if base == "go.mod":
        pkgs, own, rts, replaces = parse_go_mod(text)
        return pkgs, rts, own | replaces, None
    if base == "go.sum":
        return parse_go_sum(text), [], set(), None
    if base == "Cargo.lock":
        return parse_cargo_lock(text), [], set(), None
    if base == "poetry.lock":
        return parse_poetry_lock(text), [], set(), None
    if base == "uv.lock":
        return parse_uv_lock(text), [], set(), None
    if base == "Gemfile.lock":
        return parse_gemfile_lock(text), [], set(), None
    if re.fullmatch(r"requirements.*\.txt", base, re.I):
        return parse_requirements(base, text), [], set(), None
    if base == "pom.xml":
        return parse_pom_xml(text), [], set(), None
    if base.endswith(".csproj") or base == "Directory.Packages.props":
        return parse_dotnet_xml(text), [], set(), None
    if base == "Dockerfile" or base.startswith("Dockerfile.") or base in (".nvmrc", ".python-version", ".tool-versions"):
        return [], parse_runtime_file(base, text), set(), None
    if base in ("composer.lock", "Pipfile.lock"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return [], [], set(), None
        if isinstance(data, dict):
            fn = parse_composer_lock if base == "composer.lock" else parse_pipfile_lock
            return fn(data), [], set(), None
        return [], [], set(), None
    if base.endswith(".json"):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return [], [], set(), None
        if not isinstance(data, dict):
            return [], [], set(), None
        if data.get("bomFormat") == "CycloneDX":
            return parse_cdx(data), [], set(), None
        if "spdxVersion" in data:
            return parse_spdx(data), [], set(), None
        if base == "package-lock.json":
            return parse_npm_lock(data), [], set(), None
        if base == "packages.lock.json":
            return parse_nuget_lock(data), [], set(), None
        if base == "global.json":
            return [], parse_runtime_file(base, text), set(), None
    return [], [], set(), None


def is_scan_target(base):
    """Only open known lock files, SBOM/config JSON, XML project files and runtime files - never .env or source code"""
    if base in UNSUPPORTED_LOCKFILES:
        return True
    if base in ("go.mod", "go.sum", "Cargo.lock", "poetry.lock", "uv.lock", "Gemfile.lock",
                "composer.lock", "Pipfile.lock", "pom.xml", "Directory.Packages.props",
                "Dockerfile", ".nvmrc", ".python-version", ".tool-versions"):
        return True
    return (base.startswith("Dockerfile.") or base.endswith((".json", ".csproj"))
            or bool(re.fullmatch(r"requirements.*\.txt", base, re.I)))


def iter_target_files(root):
    if os.path.isfile(root):
        yield os.path.basename(root), root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if not is_scan_target(fn):
                continue
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            yield os.path.relpath(full, root), full


BAD_TOKEN_RE = re.compile(r"[\s|#\x00-\x1f\x7f]")


def classify_pkg(eco, name, ver, role, own_go, allow_scopes, exclude_prefixes):
    if role == "private":
        return "private", None
    if not (name and ver) or BAD_TOKEN_RE.search(name) or BAD_TOKEN_RE.search(ver):
        return "private", None
    if any(name.startswith(p) for p in exclude_prefixes):
        return "private", None
    if eco == "Go":
        if any(name == m or name.startswith(m + "/") for m in own_go):
            return "private", None
        host = name.split("/", 1)[0]
        if "." in host and host not in PUBLIC_GO_HOSTS and host not in allow_scopes:
            return "suspect", host
    if eco == "npm" and name.startswith("@") and "/" in name:
        scope = name.split("/", 1)[0]
        if scope not in allow_scopes and (scope + "/") not in allow_scopes:
            return "suspect", scope
    return ("dev" if role == "dev" else "prod"), None


def read_packages_file(path):
    pkgs = {}
    with open(path) as f:
        for raw in f:
            line = re.sub(r"(^|\s)#.*", "", raw).strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) >= 2:
                pkgs[(parts[0], parts[1])] = parts[2] if len(parts) > 2 else ""
    return pkgs


def diff_packages(old_path, new_set):
    old = read_packages_file(old_path)
    new = {(e, n): v for e, n, v in new_set}
    added = sorted(f"{e}|{n}|{v}" for (e, n), v in new.items() if (e, n) not in old)
    removed = sorted(f"{e}|{n}|{v}" for (e, n), v in old.items() if (e, n) not in new)
    updated = [{"package": f"{e}|{n}", "old": old[(e, n)], "new": v}
               for (e, n), v in sorted(new.items()) if (e, n) in old and old[(e, n)] != v]
    return {"added": added, "removed": removed, "updated": updated}


def write_packages(path, pkgs):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        for eco, name, ver in sorted(pkgs):
            f.write(f"{eco}|{name}|{ver}\n")
    os.replace(tmp, path)


def run_scan(a):
    raw_pkgs, runtimes, own_go, unsupported, files_read, errors = [], [], set(), [], [], []
    if a.stdin:
        if not a.format:
            raise SystemExit("scan --stdin needs --format FILENAME")
        pkgs, rts, own, unsup = parse_one(a.format, sys.stdin.read())
        raw_pkgs += pkgs
        runtimes += [{**r, "source": a.format} for r in rts]
        own_go |= own
        if unsup:
            unsupported.append({"file": a.format, "note": unsup})
        elif pkgs or rts:
            files_read.append(a.format)
    else:
        if not a.target:
            raise SystemExit("scan needs a path or --stdin --format FILENAME")
        files = list(iter_target_files(a.target))
        go_mod_dirs = {os.path.dirname(rel) for rel, full in files
                       if os.path.basename(rel) == "go.mod" and go_mod_lists_all(full)}
        # Ensure go.mod in a directory is parsed before go.sum in the same directory
        files.sort(key=lambda pair: (os.path.dirname(pair[0]), 0 if os.path.basename(pair[0]) == "go.mod" else 1, pair[0]))
        go_direct_by_dir = {}
        for rel, full in files:
            bname, dname = os.path.basename(rel), os.path.dirname(rel)
            if bname == "go.sum" and dname in go_mod_dirs:
                continue  # go.mod require lines already give the selected versions
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    errors.append({"file": rel, "error": f"larger than {MAX_BYTES} bytes, skipped"})
                    continue
                with open(full, encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError as e:
                errors.append({"file": rel, "error": str(e)})
                continue
            pkgs, rts, own, unsup = parse_one(rel, text)
            if bname == "go.mod":
                go_direct_by_dir[dname] = {m for _, m, _, _ in pkgs}
            elif bname == "go.sum" and dname in go_direct_by_dir:
                pkgs = [p for p in pkgs if p[1] not in go_direct_by_dir[dname]]
            raw_pkgs += pkgs
            runtimes += [{**r, "source": rel} for r in rts]
            own_go |= own
            if unsup:
                unsupported.append({"file": rel, "note": unsup})
            elif pkgs or rts:
                files_read.append(rel)

    allow = set(a.allow_scope or [])
    excl = list(a.exclude_prefix or [])
    prod, dev, suspects = set(), set(), {}
    skipped_private, skipped_dev = 0, 0
    for eco, name, ver, role in raw_pkgs:
        kind, scope = classify_pkg(eco, name, ver, role, own_go, allow, excl)
        if kind == "private":
            skipped_private += 1
        elif kind == "dev":
            skipped_dev += 1
            if ver:
                dev.add((eco, name, ver))
        elif kind == "suspect":
            s = suspects.setdefault((eco, scope), {"ecosystem": eco, "scope": scope, "names": set()})
            s["names"].add(name)
        elif ver:
            prod.add((eco, name, ver))

    if a.out:
        write_packages(a.out, prod)
    if a.dev_out:
        write_packages(a.dev_out, dev)

    by_eco = {}
    for eco, _, _ in prod:
        by_eco[eco] = by_eco.get(eco, 0) + 1
    suspect_rows = sorted(
        [{"ecosystem": v["ecosystem"], "scope": v["scope"], "count": len(v["names"]),
          "examples": sorted(v["names"])[:3]} for v in suspects.values()],
        key=lambda r: (-r["count"], r["scope"]),
    )
    report = {
        "tool_version": VERSION,
        "files_read": sorted(set(files_read)),
        "packages_count": len(prod),
        "by_ecosystem": dict(sorted(by_eco.items())),
        "skipped_dev": skipped_dev,
        "skipped_private": skipped_private,
        "suspects": suspect_rows,
        "unsupported_files": unsupported,
        "runtimes": runtimes,
        "errors": errors,
    }
    if a.out:
        report["out"] = a.out
    if a.dev_out:
        report["dev_out"] = a.dev_out
    if a.diff:
        report["diff"] = diff_packages(a.diff, prod)
    return report


# ---------- Catalog suggestion ----------

def norm_tok(s):
    s = re.sub(r"\s+\d+(?:\.\d+)*\b", "", (s or "").strip().lower())
    return re.sub(r"\s+", " ", s).strip()


def run_suggest_sources(a):
    with open(a.catalog, encoding="utf-8") as f:
        entries = json.load(f).get("entries") or []
    index = {}
    for e in entries:
        keys = [e["id"], e["name"], *(e.get("aliases") or [])]
        for k in keys:
            index[norm_tok(k)] = e
    matched, seen_ids, unmatched = [], set(), []
    feeds, ghsa, nvd = [], [], []
    for raw in [s.strip() for s in a.stack.split(",") if s.strip()]:
        entry = index.get(norm_tok(raw))
        if not entry:
            unmatched.append(raw)
            continue
        if entry["id"] in seen_ids:
            continue
        seen_ids.add(entry["id"])
        matched.append({"id": entry["id"], "name": entry["name"], "sources": entry["sources"]})
        for s in entry["sources"]:
            if s["type"] == "feed":
                line = f"{s['name']}|{s['url']}"
                if line not in feeds:
                    feeds.append(line)
            elif s["type"] == "ghsa":
                if s["repo"] not in ghsa:
                    ghsa.append(s["repo"])
            elif s["type"] == "nvd":
                line = f"{s['name']}|{s['cpe']}"
                if line not in nvd:
                    nvd.append(line)
    return {"matched": matched, "feeds": feeds, "ghsa": ghsa, "nvd": nvd, "unmatched": unmatched}


# ---------- Vendor feed discovery ----------

FEED_TYPES = ("application/rss+xml", "application/atom+xml", "application/rdf+xml", "application/xml", "text/xml")
GHSA_LINK_RE = re.compile(r"^https?://github\.com/([\w.-]+/[\w.-]+)/security/advisories/?")


class FeedLinkParser(html.parser.HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base = base_url
        self.feeds = []
        self.ghsa_repos = []

    def handle_starttag(self, tag, attrs):
        d = {k.lower(): (v or "") for k, v in attrs}
        href = d.get("href", "").strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            return
        full = urllib.parse.urljoin(self.base, href)
        if urllib.parse.urlsplit(full).scheme not in ("http", "https"):
            return
        if tag == "link":
            rel = d.get("rel", "").lower().split()
            ctype = d.get("type", "").lower().split(";", 1)[0].strip()
            if "alternate" in rel and ctype in FEED_TYPES:
                self.feeds.append({"url": full, "title": d.get("title", "").strip(), "type": ctype})
        elif tag == "a":
            m = GHSA_LINK_RE.match(full)
            if m and m.group(1) not in self.ghsa_repos:
                self.ghsa_repos.append(m.group(1))
            elif re.search(r"(\.(?:rss|atom|xml)|/feed/?)$", urllib.parse.urlsplit(full).path, re.I):
                self.feeds.append({"url": full, "title": d.get("title", "").strip(), "type": "link"})


def run_discover_feeds(url):
    raw = http_get(url).decode("utf-8", "replace")
    parser = FeedLinkParser(url)
    parser.feed(raw)
    seen, unique = set(), []
    for f in parser.feeds:
        if f["url"] not in seen:
            seen.add(f["url"])
            unique.append(f)
    return {"url": url, "feeds": unique, "ghsa_repos": parser.ghsa_repos}


# ---------- NVD CPE lookup ----------

def run_find_cpe(query, api, limit):
    nvd_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": nvd_key} if nvd_key and token_ok(api) else None
    url = api + "?" + urllib.parse.urlencode({"keywordSearch": query, "resultsPerPage": 100})
    data = json.loads(http_get(url, extra_headers=headers))
    groups = {}
    for p in data.get("products") or []:
        cpe = p.get("cpe") or {}
        if cpe.get("deprecated"):
            continue
        name = cpe.get("cpeName") or ""
        parts = name.split(":")
        if len(parts) < 5:
            continue
        prefix = ":".join(parts[:5])
        titles = cpe.get("titles") or []
        title = next((t.get("title", "") for t in titles if t.get("lang") == "en"),
                     titles[0].get("title", "") if titles else "")
        g = groups.setdefault(prefix, {"cpe": prefix, "matches": 0, "example": title})
        g["matches"] += 1
    ranked = sorted(groups.values(), key=lambda r: (-r["matches"], r["cpe"]))[:max(limit, 1)]
    return {"query": query, "prefixes": ranked}


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="extract packages and runtimes from lock files, SBOMs and Dockerfiles")
    p_scan.add_argument("target", nargs="?", help="directory or file to scan")
    p_scan.add_argument("--stdin", action="store_true", help="read one file from stdin instead of disk")
    p_scan.add_argument("--format", help="filename hint when using --stdin (for example package-lock.json)")
    p_scan.add_argument("--out", help="write production packages (ecosystem|name|version) to this file")
    p_scan.add_argument("--dev-out", help="write excluded development packages to this file")
    p_scan.add_argument("--diff", help="compare with an existing packages file and report added/removed/updated")
    p_scan.add_argument("--allow-scope", action="append", help="approve a suspect scope or Go host (repeatable)")
    p_scan.add_argument("--exclude-prefix", action="append", help="skip package names starting with this prefix (repeatable)")

    p_sug = sub.add_parser("suggest-sources", help="match stack names against catalog.json")
    p_sug.add_argument("--stack", required=True, help="comma-separated product names")
    p_sug.add_argument("--catalog", default=DEFAULT_CATALOG, help="path to catalog.json")

    p_disc = sub.add_parser("discover-feeds", help="find RSS/Atom and GHSA links on a vendor page")
    p_disc.add_argument("url", help="vendor security page URL (http or https)")

    p_cpe = sub.add_parser("find-cpe", help="look up NVD CPE 2.3 prefixes for a product")
    p_cpe.add_argument("query", help="product or vendor search text")
    p_cpe.add_argument("--max", type=int, default=10, help="max prefixes to return (default 10)")
    p_cpe.add_argument("--nvd-cpe-api", default=NVD_CPE_API, help=argparse.SUPPRESS)

    a = ap.parse_args()
    if a.command == "scan":
        out = run_scan(a)
    elif a.command == "suggest-sources":
        out = run_suggest_sources(a)
    elif a.command == "discover-feeds":
        out = run_discover_feeds(a.url)
    else:
        out = run_find_cpe(a.query, a.nvd_cpe_api, a.max)
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main()
