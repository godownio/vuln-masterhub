# Knowledge release 2026-11-13

7,060 cards (1,327 added), 168 directories, 73,486 vector chunks, complete coverage.

- Release: https://github.com/godownio/vuln-masterhub/releases/tag/cloud-snapshot-20261113
- Pages success: https://github.com/godownio/vuln-masterhub/actions/runs/43419788116
- Space success: https://github.com/godownio/vuln-masterhub/actions/runs/43419953371
- Live Pages card count and portal vector status match the release.
- Four new-card page checks passed (two cards on each site). Anonymous MCP request returned 401. No load testing.
- Local scoped semantic retrieval against this exact snapshot ranked the sampled new card first.
- Knowledge examples containing Hugo shortcode syntax are escaped as literal text during export; source Markdown is preserved. Full Hugo build passed.
- Existing account storage and credentials unchanged. The checksum-verified release bundle approach remains in use to fit the free Space Git storage limit.
