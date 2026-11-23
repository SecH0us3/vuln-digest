#!/bin/sh
# Checks the site built by site/build.sh. Run from the repository root: sh site/check.sh
set -eu

SITE='https://vuln-digest.secmy.app/'
PROMPT='Read https://vuln-digest.secmy.app/README.md and follow it: set up a scheduled vulnerability digest for me.'
LANDING=_site/index.html
DOCS=_site/docs/index.html

fail() { echo "check failed: $1" >&2; exit 1; }

# --- The landing page ---
cmp -s site/landing.html "$LANDING" || fail 'index.html differs from site/landing.html'
[ "$(grep -c '<h1' "$LANDING")" = 1 ] || fail 'the landing page must have exactly one h1'
[ "$(grep -cF "$PROMPT" "$LANDING")" = 2 ] || fail 'the landing page must show the start prompt twice, exactly as in check.sh'
grep -qF 'href="README.md"' "$LANDING" || fail 'the landing page does not link the instructions for AI'
grep -qF 'href="docs/"' "$LANDING" || fail 'the landing page does not link the instructions page'
grep -qF 'href="https://github.com/SecH0us3/vuln-digest"' "$LANDING" || fail 'the landing page does not link the repository'
grep -q '<meta name="description" content="..*">' "$LANDING" || fail 'landing: no meta description'
grep -qF "<link rel=\"canonical\" href=\"${SITE}\">" "$LANDING" || fail 'landing: no canonical link'
grep -qF "<meta property=\"og:image\" content=\"${SITE}social-preview.png\">" "$LANDING" || fail 'landing: no og:image'
grep -q '<meta name="viewport"' "$LANDING" || fail 'landing: no viewport meta'
if grep -q '<script[^>]*src=' "$LANDING"; then fail 'landing: external scripts are not allowed'; fi
if grep -qiE '(href|src)="http://' "$LANDING" _site/404.html; then fail 'plain http link'; fi

# Pages other than 404.html use relative links only, so the site works under any path
if grep -qE '(href|src)="/' "$LANDING" "$DOCS"; then fail 'use relative links: the site may be served under a path'; fi

# Every site-local link of the landing and 404 pages exists in the build
check_link() { # $1: path relative to _site
  case "$1" in
    ''|*/) file="_site/${1}index.html" ;;
    *) file="_site/$1" ;;
  esac
  [ -f "$file" ] || fail "linked file is not in the build: $1"
}
for path in $(grep -ohE '(href|src)="[^"#:]*"' "$LANDING" | sed -E 's/^(href|src)="//; s/"$//; s#^\./##' | sort -u); do
  check_link "$path"
done
for path in $(grep -ohE '(href|src)="/[^"#]*"' _site/404.html | sed -E 's/^(href|src)="//; s/"$//' | sort -u); do
  check_link "${path#"${BASE_PATH:-}"/}"
done

# Every in-page anchor of the landing page has a target
for id in $(grep -oE 'href="#[^"]+"' "$LANDING" | sed -E 's/href="#//; s/"$//' | sort -u); do
  grep -qE "id=\"$id\"" "$LANDING" || fail "anchor without target: #$id"
done

# The helper script size claim on the landing page stays true (about 700 lines)
lines="$(wc -l < tools/vuln_feed.py)"
[ "$lines" -ge 620 ] && [ "$lines" -le 800 ] || fail "vuln_feed.py has $lines lines: update the landing page text"

# --- The instructions page ---
grep -qF '<nav class="site-header"' "$DOCS" || fail 'the instructions page has no header with a link to the landing page'
grep -qF 'href="https://github.com/SecH0us3/vuln-digest"' "$DOCS" || fail 'no repository link on the instructions page'
grep -qF 'ecosystem|name|version' "$DOCS" || fail 'package line format lost'
[ "$(grep -c '<h1' "$DOCS")" = 1 ] || fail 'the instructions page must have exactly one h1'
toc="$(sed -n '/<nav id="TOC"/,/<\/nav>/p' "$DOCS")"
echo "$toc" | grep -q 'Step 1\.' || fail 'table of contents has no steps'
echo "$toc" | grep -q '>Run<' || fail 'table of contents has no Run section'
if echo "$toc" | grep -q 'scheduled vulnerability reports'; then fail 'table of contents repeats the document title'; fi
grep -q '<meta name="description" content="..*">' "$DOCS" || fail 'docs: no meta description'
grep -qF "<link rel=\"canonical\" href=\"${SITE}docs/\">" "$DOCS" || fail 'docs: no canonical link'
grep -qF "<meta property=\"og:image\" content=\"${SITE}social-preview.png\">" "$DOCS" || fail 'docs: no og:image'
grep -qF 'href="../style.css"' "$DOCS" || fail 'docs: no stylesheet link'
grep -qF 'href="../"' "$DOCS" || fail 'docs: no link back to the landing page'

# --- Icons and the preview image ---
for f in favicon.svg favicon-32.png apple-touch-icon.png social-preview.png style.css landing.css 404.html; do
  [ -s "_site/$f" ] || fail "missing file: $f"
done
# PNG stores width and height as two 4-byte numbers starting at byte 17
[ "$(od -An -tu1 -j16 -N8 _site/social-preview.png | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')" = '0 0 4 176 0 0 2 118' ] || fail 'social-preview.png must be 1200x630'

# --- Copies for agents ---
cmp -s README.md _site/README.md || fail 'README.md copy differs'
cmp -s README.md _site/index.md || fail 'index.md differs from README.md'
cmp -s README.md _site/llms-full.txt || fail 'llms-full.txt differs from README.md'
cmp -s AGENTS.md _site/AGENTS.md || fail 'AGENTS.md copy differs'
cmp -s tools/vuln_feed.py _site/vuln_feed.py || fail 'vuln_feed.py copy differs'
# version.json holds the checksums of the published README.md and vuln_feed.py
for f in README.md vuln_feed.py; do
  sum="$(sha256sum "_site/$f" | cut -d' ' -f1)"
  grep -qF "\"$f\": \"$sum\"" _site/version.json || fail "the sha256 of $f in version.json is out of date"
done
cmp -s site/version.json _site/version.json || fail 'version.json copy differs'

# Running jobs compare the Version line of their copy of README.md with version.json
grep -qF "${SITE}version.json" README.md || fail 'README.md does not link version.json'
readme_version="$(sed -n 's/^Version: \([0-9][0-9.]*[0-9]\)\. .*/\1/p' README.md | head -n 1)"
[ -n "$readme_version" ] || fail 'README.md has no Version line'
grep -qF "\"version\": \"$readme_version\"" _site/version.json || fail "version.json does not list version $readme_version as current"

# The README tells agents where the script and the instructions live
grep -qF "${SITE}vuln_feed.py" README.md || fail 'README.md does not link the helper script'
grep -qF "${SITE}README.md" README.md || fail 'README.md does not give its own address for the job prompt'

# llms-full.txt starts with an H1 and has H2 sections
head -n 1 _site/llms-full.txt | grep -q '^# ' || fail 'llms-full.txt does not start with an H1'
grep -q '^## ' _site/llms-full.txt || fail 'llms-full.txt has no H2 sections'

# llms.txt: exactly one H1, a blockquote, a link list
[ "$(grep -c '^# ' _site/llms.txt)" = 1 ] || fail 'llms.txt must have exactly one H1'
grep -q '^> ' _site/llms.txt || fail 'llms.txt has no blockquote'
grep -q '^- \[' _site/llms.txt || fail 'llms.txt has no link list'

# Every link in llms.txt and sitemap.xml that points to this site exists in the build
for url in $(grep -ho "${SITE}[^)<\"]*" _site/llms.txt _site/sitemap.xml | sort -u); do
  path="${url#"$SITE"}"
  case "$path" in
    ''|*/) path="${path}index.html" ;;
  esac
  [ -f "_site/$path" ] || fail "linked file is not in the build: $url"
done

# robots.txt: every group has a rule, and the sitemap line is absolute
grep -q "^Sitemap: ${SITE}sitemap.xml$" _site/robots.txt || fail 'robots.txt has no Sitemap line'
[ "$(grep -c '^User-agent: ' _site/robots.txt)" = "$(grep -c '^Allow: \|^Disallow: ' _site/robots.txt)" ] || fail 'robots.txt: a group has no rule'

# ai.txt agrees with robots.txt: neither file forbids anything
cmp -s site/ai.txt _site/ai.txt || fail 'ai.txt copy differs'
if grep -q '^Disallow:' _site/robots.txt _site/ai.txt; then fail 'robots.txt and ai.txt must not forbid anything: the policy is allow all'; fi

echo 'all checks passed'
