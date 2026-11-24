RDP Wrapper Upstream Monitor v1.2.2

Purpose
- Monitor public stascorp/rdpwrap Issues and comments.
- Extract and deduplicate INI candidates.
- Compare every stored unique candidate with this repository's production rdpwrap.ini.
- Produce a GitHub Actions Summary and production-comparison.json.

The comparison baseline is the rdpwrap.ini checked out by actions/checkout at the exact workflow commit. It is not downloaded from another URL. The monitor never edits, installs, or publishes rdpwrap.ini.

Install the three replacement files listed in INSTALL-中文说明.txt. Preserve monitor-state.json and compatibility-candidates.json.
