# Event fixtures

**These are synthetic test inputs, not telemetry captured from a real host.**

- `sysmon_*.xml`, `system_*.xml`, `security_*.xml` follow the XML that
  `EvtRender(EvtRenderEventXml)` produces, with field names from the
  Sysmon 15 and Windows event schemas. The 7045 sample mirrors the
  structure of a real 7045 event read from the development host. The
  service, paths, host and hashes are invented.
- Hosts, users, hashes, IPs (RFC 5737 documentation ranges) and paths
  are fictitious.
- `hostile_*.xml` are deliberately malicious or broken inputs (entity
  expansion, external entity, truncated document) used to test the parser's
  hardening.

The scenario (an `updater.exe` in `%TEMP%` that loads an unsigned DLL,
injects into explorer, opens LSASS and sets a Run key) exists only to give
the parser and normalisers realistic field combinations. It isn't a
detection test.
