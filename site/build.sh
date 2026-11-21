#!/bin/sh
# Builds the site into _site/. Run from the repository root: sh site/build.sh
# Needs Docker with a running daemon.
set -eu

PANDOC_IMAGE='pandoc/core:3.11.0@sha256:62518bfb6833705dc90a1634d8d879299bd820b3f74ad3b32fba8b618452553a'

mkdir -p _site/docs

# The landing page for people. Hand-written HTML, published as it is
cp site/landing.html _site/index.html
cp site/landing.css _site/landing.css
cp site/404.html _site/404.html

# The instructions rendered for people, at /docs/
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/data:ro" \
  -v "$PWD/_site:/out" \
  "$PANDOC_IMAGE" \
  --from gfm --to html5 --standalone \
  --toc --toc-depth=2 \
  --lua-filter site/toc.lua \
  --metadata pagetitle="vuln-digest - scheduled vulnerability reports for AI agents" \
  --metadata lang=en \
  --css /style.css \
  --include-in-header site/head.html \
  --include-after-body site/footer.html \
  --output /out/docs/index.html \
  README.md
cp site/style.css _site/style.css

# Icons and the preview image for social networks. The PNG files are rendered from the SVG files next to them
cp site/assets/favicon.svg site/assets/favicon-32.png site/assets/apple-touch-icon.png site/assets/social-preview.png _site/

# The instructions as plain Markdown, for agents. All copies come from README.md
cp README.md _site/README.md
cp README.md _site/index.md
cp README.md _site/llms-full.txt

# Files published as they are
cp AGENTS.md _site/AGENTS.md
cp site/llms.txt _site/llms.txt
cp site/robots.txt _site/robots.txt
cp site/ai.txt _site/ai.txt
cp site/sitemap.xml _site/sitemap.xml

# The helper script, so agents can download it next to the instructions
cp tools/vuln_feed.py _site/vuln_feed.py
