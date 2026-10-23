# Operations: install, run, troubleshoot

## Install (once)

```powershell
# 1. Backend
cd server
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m app.db.migrate

# 2. Sysmon + read access (ELEVATED PowerShell, repo root), then sign out and back in
powershell -ExecutionPolicy Bypass -File .\server\scripts\setup-sysmon.ps1 -GrantEventLogRead

# 3. Dashboard
cd client; npm install
```

Security 4688 needs "Audit Process Creation" (already enabled on the
development host).

## Run

| Process | Command (from `server/` or `client/`) | Notes |
|---|---|---|
| Collector | `.\.venv\Scripts\python.exe -m app.collectors` | Needs Event Log Readers (or elevation) for Sysmon/Security |
| API | `.\.venv\Scripts\python.exe -m app` | Binds 127.0.0.1:8000 only |
| Dashboard | `npm run build; npm run start` | http://localhost:3000 |

Maintenance: `python -m app.services.backup` (online backup, keeps 7),
`python -m app.detection rescan` (after rule changes),
`python -m app.db.migrate` (after upgrades).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Sensor `unavailable` (sysmon) | Sysmon not installed | Run the setup script elevated |
| Sensor `access_denied` | Account not in Event Log Readers, **or not signed out since being added** | Setup script `-GrantEventLogRead`, then a full sign-out. Locking the screen does not refresh group membership |
| Get-WinEvent says the Sysmon log "does not exist" but `wevtutil gl Microsoft-Windows-Sysmon/Operational` works | Same as above: access denied is reported as "not found" | As above |
| Sensor `ok · stale`, "collector is not polling" | Collector not running | Start the collector |
| `records_missed` > 0 | Channel rotated before collection | `wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456` (elevated) or poll more often |
| `detection_failures` > 0 | Engine error during a batch (events were kept) | `python -m app.detection rescan` and check collector logs |
| `/health` 503, schema error | Database not migrated | `python -m app.db.migrate` |
| Dashboard "API unreachable" | API not running, or a different URL | Start the API, or set `NEXT_PUBLIC_KG_API_URL` and rebuild |

## Measured on the development host (2026-10-24, live Sysmon 15.22)

- **Telemetry volume:** about 900–1,000 Sysmon events/min during interactive
  use (image loads 31%, process access 17%, raw disk reads 14%, network 14%),
  about **5–7 GB/day** at roughly 4.8 KB/event. The default 500k-row cap holds
  about 8–9 hours. **Recommended Sysmon config trims** (apply with the setup
  script, elevated):
  - set `RawAccessRead` to `include` with no rules (138/min, no rule uses it);
  - restrict `ProcessAccess` to `lsass.exe` plus `CallTrace` containing `UNKNOWN`
    *and* a non-query access mask (Sysmon filters can't test bits, so this
    stays a KernelGuard-side filter today).
- **Processing:** about 280–300 events/s for ingestion with detection on real
  telemetry (about 17 events/s arrive), so the collector keeps up with
  roughly 15× headroom. An idle cycle takes about 10 ms.
- **Alert volume:** 23.8 minutes, 21,399 Sysmon events, same events replayed
  through each rule version:

  | Rules | Alerts | Per hour |
  |---|---|---|
  | v1 (as shipped) | 1,564 | ~3,900 |
  | v2 (first tuning) | 88 | ~220 |
  | v3 (current) | **9** | **~23** |

  All v1 and v2 alerts were reviewed and judged false positives. What
  changed in each rule is in `docs/detection.md`. The 9 remaining are
  low-confidence KG-INJ-002 alerts: parent/child pairs whose creation fell
  outside the window, and one remote-control tool (Remote Mouse) opening
  winlogon. These are documented rather than suppressed.
- **Caveat:** about 25 minutes on one developer workstation, including this
  assistant's own git and PowerShell activity. No true-positive malware
  activity was present, so detection *recall* on real attacks is **not**
  measured. The rules' positive cases are covered only by the synthetic
  tests (274 passing).
