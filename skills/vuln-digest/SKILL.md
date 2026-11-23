---
name: vuln-digest
description: Set up, change or update a scheduled digest of new vulnerabilities for the user's stack. Use when the user asks for a vulnerability or CVE digest, security alerts for what they run, or to update vuln-digest.
---

# vuln-digest

The instructions are one document: `README.md` at the root of this plugin, two levels up from this skill's directory (`../../README.md`). The helper script is `../../tools/vuln_feed.py`. Read the whole `README.md` and follow it. These files are the version the user installed, so use them instead of downloading the same files from https://vuln-digest.secmy.app/

If `../../README.md` is not there (for example, the skill was uploaded on its own to the Claude app), read https://vuln-digest.secmy.app/README.md and download https://vuln-digest.secmy.app/vuln_feed.py instead

Three rules come on top of the document:

- in steps 0 and 1, ask with the `AskUserQuestion` tool whenever you have it: one call per round from "How to ask", at most four questions per call, two to four short options per question with the default first and marked "(Recommended)", and a header of at most 12 characters. The user can always type their own answer. Use plain text only for free-text answers such as the stack list, or if the tool is missing. Never print all the questions as one table

- in step 6, copy `README.md` and `vuln_feed.py` next to the state, as the document says, and point the scheduled job at those copies. Never point the job at files inside this plugin's directory: a plugin update replaces them, and the job would change without the user seeing what changed
- when the user asks to update an existing digest, follow the "Updates" section of the document. The new version is this plugin's `README.md` and `tools/vuln_feed.py` if the plugin was updated, otherwise the files on the site
