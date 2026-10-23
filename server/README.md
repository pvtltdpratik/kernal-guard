# KernelGuard server

FastAPI backend for KernelGuard: telemetry collection, normalisation, detection,
correlation and the REST API consumed by `../client`.

**Status: Phase 3.** Event collection (Sysmon, System, Security channels),
normalisation, deduplication and retention work. On top of that: process
tracking, 16 detection rules, incident correlation, explainable scoring and the
full `/api/v1` surface. See `../docs/detection.md` for rules, scoring and the
capability matrix.

## Requirements

- Windows 10/11
- Python 3.10+ (3.12 recommended; developed and tested on 3.10.0 so far)
- Optional: Sysmon 15+ for rich telemetry (see `config/sysmon/README.md`)

## Setup (PowerShell)

```powershell
cd server
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
Copy-Item .env.example .env              # optional; defaults work without it
.\.venv\Scripts\python.exe -m app.db.migrate
```

## Run

Two processes: the collector (reads event logs, writes the DB) and the API
(reads the DB). They share only the SQLite database.

```powershell
# Terminal 1: collector. Run elevated to read the Sysmon and Security channels.
cd server
.\.venv\Scripts\python.exe -m app.collectors

# Terminal 2: API on http://127.0.0.1:8000 (docs at /docs)
cd server
.\.venv\Scripts\python.exe -m app
```

Useful collector options:

```powershell
.\.venv\Scripts\python.exe -m app.collectors --once                  # one cycle, JSON summary
.\.venv\Scripts\python.exe -m app.collectors --sensors system,sysmon # subset
```

`python -m app` reads host/port from validated settings, so the loopback-only
guard always applies. Binding to a non-loopback address is refused unless
`KG_ALLOW_REMOTE_BIND=true`. Don't set that until authentication and TLS exist
(see `../docs/security.md`).

## Sensors

| Sensor    | Channel                                | Events                          | Needs |
|-----------|----------------------------------------|---------------------------------|-------|
| `sysmon`  | `Microsoft-Windows-Sysmon/Operational` | All Sysmon events except 24 (clipboard) | Sysmon installed; admin or Event Log Readers |
| `system`  | `System`                               | 7045 service installed, 104 log cleared | Standard user |
| `security`| `Security`                             | 4688 process created, 4697 service installed, 1102 audit log cleared | Admin or Event Log Readers; audit policy for 4688/4697 |

A missing or unreadable channel is reported as `unavailable` or
`access_denied` in `/api/v1/sensors/status`. It doesn't stop the other sensors.

### Collection guarantees

- **Resume:** a per-channel bookmark (last EventRecordID + its TimeCreated) is
  committed in the same transaction as the events it covers.
- **Deduplication:** `dedup_key = sha256(host|channel|record_id|TimeCreated|EventID)`
  with a unique constraint. Re-reading after a crash stores nothing twice.
- **Log rotation:** records overwritten before collection are counted in
  `records_missed`.
- **Cleared logs:** detected (newest ID below the bookmark, or the bookmarked
  record's timestamp changed). The bookmark is reset so new events aren't
  skipped.
- **Hostile input:** size limit before parsing; DTDs and entities are rejected
  (defusedxml); field values capped (`collection_status = truncated`). Records
  that fail to parse are counted and skipped and never block the channel.
- **Read-only:** the collector never writes to, clears or reconfigures event
  logs, processes or files.

## API

All list endpoints take `page`/`page_size` and return `{items, page, page_size, total}`.
Timestamps in filters must include a timezone. Errors use the standard
`{"error": {...}}` envelope.

| Endpoint | Notes |
|---|---|
| `GET /health` | API, database and schema version |
| `GET /api/v1/events` | `sort` (`[-]timestamp`, `[-]ingested_at`, `[-]source_event_id`); filters `category` (repeatable), `source`, `channel`, `source_event_id`, `process_guid`, `process_id`, `image`, `host_id`, `since`/`until` |
| `GET /api/v1/events/{id}` | `include_raw=true` adds the original event XML |
| `GET /api/v1/alerts` | `sort` (`[-]last_seen`, `[-]first_seen`, `[-]risk_score`, `[-]severity`); filters `status`, `severity` (repeatable), `rule_id`, `host_id`, `process_guid`, `incident_id`, `q`, `min_score`, `since`/`until` |
| `GET /api/v1/alerts/{id}` | Rule explanation, observations, uncertainty, ATT&CK, score breakdown, evidence events, history |
| `PATCH /api/v1/alerts/{id}` | `{"status": "new\|acknowledged\|reviewed\|false_positive", "note": "..."}`; rescores the incident |
| `GET /api/v1/incidents` | `sort` (`[-]last_seen`, `[-]risk_score`, `[-]severity`); filters `status`, `severity`, `host_id`, `q`, `min_score`, `since`/`until` |
| `GET /api/v1/incidents/{id}` | Timeline (events + alerts), rules fired, score breakdown, uncertainty, history |
| `PATCH /api/v1/incidents/{id}` | `{"status": "open\|investigating\|closed", "note": "..."}` |
| `GET /api/v1/processes` / `{id}` | Process metadata, parent/children, event counts, network summary, signature, alerts, conflicts |
| `GET /api/v1/sensors/status` | Per-sensor state, counters (including `detection_failures`), staleness |
| `GET /api/v1/metrics/overview` | `window=24h\|7d`: totals, active alerts by severity, open and recent incidents, sensors, event volume, top rules |
| `GET /api/v1/detection/rules` | Rule catalog with rationale, false positives, thresholds |
| `GET /api/v1/detection/capabilities` | Capability matrix with effective visibility on this host |

## Detection maintenance

```powershell
.\.venv\Scripts\python.exe -m app.detection rescan                                   # all stored events
.\.venv\Scripts\python.exe -m app.detection rescan --since 2026-10-01T00:00:00+00:00
```

Rescan is idempotent. Use it after changing rules or thresholds, or when a
sensor reports `detection_failures`. Rule overrides and allowlists:
`config/detection/detection.json` (copy `detection.example.json`).

## Test

```powershell
cd server
.\.venv\Scripts\python.exe -m pytest                       # unit + fixture tests
$env:KG_LIVE_TESTS="1"; .\.venv\Scripts\python.exe -m pytest  # also read this host's System log
```

Fixtures in `tests/fixtures/events/` are synthetic (see the README there).

## Maintenance

```powershell
.\.venv\Scripts\python.exe -m app.db.migrate             # apply migrations
.\.venv\Scripts\python.exe -m app.services.backup        # online backup -> data\backups (keeps 7)
.\.venv\Scripts\alembic.exe revision --autogenerate -m "describe change"
```

Retention runs inside the collector every 15 minutes: events older than
`KG_EVENT_RETENTION_DAYS`, then the oldest beyond `KG_EVENT_MAX_ROWS`, are
deleted. Measured storage is about 4.7 KB per event including raw XML.

## Layout

```
app/
  __main__.py            python -m app (API)
  main.py                application factory
  api/routes/            health, events, sensors
  collectors/
    __main__.py          python -m app.collectors (collector process)
    base.py              EventLogReader / SensorSpec interfaces, errors
    eventlog_api.py      Windows Evt* API reader (only Windows-specific code)
    xml_parser.py        hardened event XML parser
    sysmon.py            Sysmon normaliser (table-driven per event ID)
    windows_eventlog.py  System/Security normalisers
    registry.py          sensor definitions
    runner.py            polling loop + retention scheduling
    host.py              MachineGuid host ID
  core/                  config, logging, errors, middleware
  db/                    models, UTC column type, session, migrations helper
  schemas/               Pydantic API/event schemas
  services/              ingestion, event queries, retention, backup
config/sysmon/           Sysmon configuration for KernelGuard
migrations/              Alembic
tests/                   pytest suite and fixtures
```
