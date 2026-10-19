# Changelog

## V1.0 - 2026-10-16

- First standalone public package, derived from the development V20.1 sniffer.
- Passive reader-context decoding and per-response MAD transition decoding.
- Require two matching complete E0 reads and two matching complete E8 reads,
  from distinct reader commands, before offering EM4100 export.
- Preserve Paxton odd-parity and digit-format checks, and reject tied winners.
- Include the custom Unleashed 093 firmware, API 88.11, and its source patch.
- Rename the application, FAP metadata and diagnostic directory for publication.
- No changes to RF topology, sampling rate, thresholds or decoding algorithms.

This is a release packaging change, not a claim of improved read reliability.
