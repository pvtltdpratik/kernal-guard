# KernelGuard

Windows 10/11 endpoint monitoring and threat detection. KernelGuard collects
documented Windows telemetry (Sysmon and the Windows Event Log), normalises it,
correlates related activity and applies explainable detection rules. Results
are shown in a local dashboard.

KernelGuard reports **observations** and **suspected** threats. A single event
does not prove malware is present, and the current sensors cannot see every
keylogging or spyware technique. Monitoring is read-only: it never captures
keystrokes, kills processes or deletes files.

## Repository

| Path      | Contents                                         |
|-----------|--------------------------------------------------|
| `client/` | Next.js 16 + shadcn/ui (Base UI) dashboard       |
| `server/` | FastAPI + SQLAlchemy backend, collectors, engine |
| `docs/`   | Architecture, security and roadmap notes         |

## Quick start (PowerShell)

Backend (first time: see `server/README.md` for setup and migration):

```powershell
cd server
.\.venv\Scripts\python.exe -m app.collectors   # collector (elevate for Sysmon/Security)
.\.venv\Scripts\python.exe -m app              # API on http://127.0.0.1:8000
```

Frontend:

```powershell
cd client
npm install
npm run dev                                 # http://localhost:3000
```

## Status

| Phase | Scope                                     | State       |
|-------|-------------------------------------------|-------------|
| 1     | Backend scaffold, config, logging, health | Done        |
| 2     | Event schema, Sysmon/EventLog ingestion   | Done        |
| 3     | Rule engine, correlation, scoring         | Done        |
| 4     | Dashboard integration                     | Done        |
| 5     | Validation and performance                | Done (see docs/operations.md) |

Sysmon (optional but needed for most detections), from an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\server\scripts\setup-sysmon.ps1 -GrantEventLogRead
```

See `docs/architecture.md` for design decisions, `docs/detection.md` for
rules, scoring, the capability matrix and known detection gaps, and
`docs/frontend.md` for the dashboard.
