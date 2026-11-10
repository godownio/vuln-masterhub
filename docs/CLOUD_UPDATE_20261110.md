# Knowledge release 2026-11-10

Published 5,733 cards (2,093 added), 168 directories and 59,297 vector chunks with full coverage.

- Release: https://github.com/godownio/vuln-masterhub/releases/tag/cloud-snapshot-20261110
- Pages success: https://github.com/godownio/vuln-masterhub/actions/runs/42796785229
- Portal runtime success: https://github.com/godownio/vuln-masterhub/actions/runs/42797401430
- Both live indexes report 5,733 cards. Two newly added card pages on each site returned HTTP 200 with matching titles.
- Anonymous MCP request returned 401. No load testing was performed.
- Local search against the identical verified snapshot used semantic retrieval and ranked the sampled new card first.

The Space keeps a lightweight application and a release pointer to avoid its 1 GB Git storage limit. On startup it downloads the public release bundle, verifies SHA256 and extracts only knowledge data, indexes and static frontend files. Existing account storage and secrets are unchanged. Cold startup requires GitHub access and can take longer.
