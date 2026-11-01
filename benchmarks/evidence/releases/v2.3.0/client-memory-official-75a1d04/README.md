# Official vectored-upload candidate residency

Eight rotated process runs compare official GNU `75a1d04` with the official
`d72abc2` baseline after verified HTTPS transfers through Chrome LINEs.
All 3,072 transfers and 1,024 unique upload receipts validate; all eight clients
recover the initial FD count after closing 128 held connections.

`assessment.json` retains every per-run residency observation. These samples
are not allocation counts, timing results or a long-term leak verdict. The
private certificate, configuration and process-log directory is excluded.
