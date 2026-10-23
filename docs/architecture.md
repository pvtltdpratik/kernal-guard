# KernelGuard architecture

## Layers

```
Windows telemetry (Sysmon, Event Log; ETW later)
        │  collectors/  (read-only, bookmarked, behind a common interface)
        ▼
Normalised events (common schema, nullable optional fields)
        │  detection/  (rules → correlation → explainable scoring)
        ▼
SQLite via SQLAlchemy (events, alerts, incidents, sensor health)
        │  api/  (FastAPI, /api/v1, loopback only)
        ▼
client/ (Next.js dashboard)
```

Collection, detection, persistence, API and presentation stay in separate
modules. A collector never calls the API, and the API never runs collection
or response actions directly.

## Phase 1 decisions

| Decision | Reason |
|---|---|
| `python -m app` entry point instead of bare `uvicorn` | Host/port pass through `Settings` validation, so the API can't bind to a non-loopback address unless someone opts in. |
| Remote binding refused unless `KG_ALLOW_REMOTE_BIND=true` | The API has no authentication yet. Failing closed is safer than relying on documentation. |
| CORS allowlist, wildcard rejected, only `GET`/`PATCH`, no credentials | Matches the planned API surface. The browser dashboard is the only intended cross-origin caller. |
| SQLite with WAL, `foreign_keys=ON`, `busy_timeout` | The collector writes while the API reads. WAL avoids reader/writer blocking on a single host. |
| Alembic with `render_as_batch` and a constraint naming convention | SQLite can't ALTER constraints in place. Batch mode plus stable names keeps migrations reproducible. |
| JSON log lines with request IDs | Logs are machine-parseable, and API errors can be traced to log lines via `X-Request-ID`. |
| Uniform `{"error": {...}}` envelope; 500s never include exception text | Clients get a consistent contract and internals don't leak. |
| `/health` covers only API + database | Sensor/collector health is a separate concern (`/api/v1/sensors/status`, Phase 2). An API that is up while Sysmon is missing should still report healthy. |

## Phase 2 decisions

| Decision | Reason |
|---|---|
| Collector and API run as separate processes, sharing only SQLite | Only the collector needs elevated read access to protected channels. The API stays unprivileged. |
| Resume by EventRecordID (`EventRecordID > N` XPath) instead of opaque `EvtBookmark` XML | Record IDs only increase within a channel, are plain integers, and are easy to test. Clears and rotation are detected explicitly instead. |
| Bookmark committed in the same transaction as its events | A crash re-reads at most one batch, and the dedup key drops what was already stored. |
| Dedup key includes TimeCreated, not just record ID | A cleared log restarts numbering, so a new event can reuse an old ID. |
| `records_missed` from oldest-record gap | Log rotation silently loses telemetry. Making the loss visible is required for honest coverage claims. |
| Poison records skipped using a regex-extracted record ID | One malformed record must never block a channel. |
| defusedxml, size cap before parse, per-field caps | Event XML is untrusted input (other software can write events). |
| Table-driven Sysmon normaliser; all original fields kept in `data` | Adding an event type is a one-line table entry, and no evidence is dropped during normalisation. |
| Hash/signature columns describe the event's *subject file* | Event 1 = process image; 6/7 = loaded module. This is documented per event so it can't be misread. |
| Sysmon 24 (clipboard) explicitly not collected | It relates to clipboard contents. Excluded by the privacy rules. |
| `UTCDateTime` column type | SQLite drops timezones. Naive datetimes are rejected on write, and values come back as aware UTC. |
| Core `executemany` insert with `ON CONFLICT DO NOTHING RETURNING` | Measured 3.5× faster than a multi-row VALUES insert (295 → 1,050 events/s). Inserted vs duplicate counts stay exact. |
| `/health` includes schema revision | An unmigrated database returns 503 with the fix command instead of failing with 500s. |

### Measured (development host, synthetic Sysmon events, SQLite on SSD)

- Ingestion: ~1,050 events/s end to end (parse, normalise, insert), batch size 500.
- Idle cycle (nothing new): ~12 ms per channel.
- Storage: ~4.7 KB/event with raw XML stored.
- Live: 72 real System 7045 events ingested in one cycle (~1.9 s, including
  the 37k-record channel scan for EventID filtering); the second cycle read 0.

## Phase 3 decisions

| Decision | Reason |
|---|---|
| Detection runs inline per ingested batch, inside a SAVEPOINT | No separate cursor or queue to keep in sync. An engine failure can't block ingestion and is counted for rescan. |
| pysqlite `BEGIN` handled by SQLAlchemy (documented recipe) | Python's sqlite3 module mishandles SAVEPOINT otherwise. |
| Rules are Python classes with declarative `RuleMeta` | Each rule's rationale, false positives, thresholds and ATT&CK mapping live next to its logic and are served by the API. Rules are testable through the real pipeline. |
| `observed` / `inferred` observations and `observed` / `consistent_with` ATT&CK | Keeps confirmed facts apart from interpretation, as the brief requires. |
| Alert dedup by (rule, host, subject); occurrences only for *new* evidence | Duplicate events and rescans don't inflate counts or scores. |
| Incident = shared entity (process GUID/PID+start, parent, file) within a window | Explainable grouping that is safe under PID reuse. |
| Incident score counts each rule once; false positives contribute 0 | Repeated evidence isn't independent, and analyst verdicts resolve conflicting evidence. |
| Capability matrix combined with live sensor health | Reports what is observable *on this host now*, not in theory. |
| Expression indexes on `json_extract(data, ...)` for correlation lookups (migration 0003) | Per-event lookups were quadratic. A query-plan test guards that the index stays in use. |
| Investigation history is append-only (`investigation_actions`) | Status changes and notes are auditable. Actor is `local` until auth exists. |

## Environment observations (2026-10-23, development host)

- Python 3.10.0 is the only interpreter installed. Upstream support for 3.10
  ends in October 2026, so move to 3.12. The code avoids 3.11+-only APIs so the
  move needs no changes.
- Sysmon 15.22 binaries (Microsoft-signed) are in `C:\Program Files\sysmon`
  and on PATH, but the driver and service are **not installed**, so the
  channel doesn't exist and the collector reports `unavailable`. The
  KernelGuard config and normaliser field names were validated against
  `Sysmon64.exe -s` (schema 4.91).
- The session is not elevated, so the Security channel reports `access_denied`.
- The System log has wrapped (oldest record 245891), which confirms that
  rotation loss is a real concern on ordinary hosts.
