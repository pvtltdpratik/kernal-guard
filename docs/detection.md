# Detection

KernelGuard reports **observations** and **suspected** activity. No alert by
itself claims that malware is present. Every alert separates:

- `observed`: statements backed by a stored event (each cites its `event_id`)
- `inferred`: the rule's interpretation
- `uncertainty`: what the evidence cannot show

MITRE ATT&CK mappings carry a `relationship`. `observed` means the event *is*
the technique (for example, a Run key was written). `consistent_with` means the
evidence fits the technique but has other explanations.

## Pipeline

```
batch of new events (same DB transaction as ingestion, inside a SAVEPOINT)
  -> ProcessTracker   build/merge process records (GUID or PID+start keyed)
  -> event rules      per event category
  -> alerts           dedup by (rule, host, subject); repeats bump occurrence_count
  -> correlation      alerts sharing an entity within the window join an incident
  -> correlation rules (KG-SPY-002) over each touched incident
  -> incident rescore
```

If a rule raises an exception, it's logged and counted as a rule error, and
the other rules still run. If the engine itself fails, the savepoint rolls back
the detection writes only. Events and bookmarks still commit, and the sensor's
`detection_failures` counter tells you to run
`python -m app.detection rescan`.

## Rules

| ID | Category | Default severity / confidence | Fires when | ATT&CK |
|---|---|---|---|---|
| KG-EXEC-001 | executable | low / low | Process image in Temp, Users\Public, ProgramData root, Recycle Bin, PerfLogs, Roaming root | — |
| KG-DRV-001 | executable | high / medium | Driver loaded with `Signed=false` or `SignatureStatus != Valid` | — |
| KG-PERSIST-001 | persistence | medium / low (high / medium with risk factors) | Value set under Run/RunOnce/Policies\Explorer\Run | T1547.001 observed |
| KG-PERSIST-002 | persistence | medium / medium | File created in a Startup folder (not desktop.ini) | T1547.001 observed |
| KG-PERSIST-003 | persistence | high / medium | Service installed **and** binary is user-writable, runs via a script host or LOLBin, uses `%COMSPEC%` or a UNC path | T1543.003 observed |
| KG-PERSIST-004 | persistence | high / medium (COM: medium / low) | IFEO Debugger, SilentProcessExit, Winlogon Shell/Userinit/Notify (non-default), AppInit_DLLs, UserInitMprLogonScript, per-user InprocServer32 | T1546.012, T1547.004, T1546.010, T1037.001, T1546.015 |
| KG-PERSIST-005 | persistence | medium / medium (high for command/script consumers) | WMI consumer or binding created | T1546.003 observed |
| KG-INJ-001 | injection | medium / medium (high if start address is unbacked) | Remote thread, source not csrss/wininit/services/smss/Defender | T1055 consistent_with |
| KG-CRED-001 | injection | high / medium (critical with dbghelp/UNKNOWN call trace) | lsass.exe opened with PROCESS_VM_READ by a non-system process | T1003.001 consistent_with |
| KG-INJ-002 | injection | medium / low | Process access call trace contains `UNKNOWN(` (target not LSASS) | T1055 consistent_with |
| KG-NET-001 | network | medium / low | Outbound connection to a global IP from a user-writable image | — |
| KG-NET-002 | network | medium / medium | Outbound global connection from PowerShell, mshta, rundll32, regsvr32, certutil, bitsadmin, wscript, cscript | per binary, consistent_with |
| KG-FILE-001 | file | informational / low | Executable or script written to a user-writable path | — |
| KG-FILE-002 | file | medium / medium | A process starts from a file written up to 24 h earlier (matched in both directions, so out-of-order delivery works) | — |
| KG-SPY-001 | spyware | medium / low | Same unsigned or user-writable DLL loaded by ≥3 distinct processes within ±10 min | T1056.001, T1055.001 consistent_with |
| KG-SPY-002 | spyware (correlation) | high / medium | An incident's active alerts span ≥3 behaviour categories, including persistence | — |

Full rationale, required evidence and false-positive guidance per rule:
`GET /api/v1/detection/rules`.

### Deliberate exclusions

- `curl.exe` (developer tool shipped with Windows) and `msiexec.exe` (routine
  installer downloads) are not treated as network LOLBins.
- Normal service installs are not alerted. On the development host, all 72
  real 7045 events (WindowsApps, Program Files, System32, vendor ProgramData
  subfolders) produced no alerts.
- Per-user application folders (`AppData\Local\<Vendor>`) are not
  "user-writable" for EXEC-001: Electron and Squirrel apps legitimately run
  from there.
- Signed DLLs in protected paths never trigger SPY-001 (IMEs, accessibility
  and shell extensions).

## Scoring

**Alert:** `(severity points + adjustments) × confidence multiplier`, capped at 100.

| Severity | Points | | Confidence | Multiplier |
|---|---|---|---|---|
| informational | 10 | | low | 0.6 |
| low | 25 | | medium | 0.8 |
| medium | 50 | | high | 1.0 |
| high | 75 | | | |
| critical | 90 | | | |

Adjustments are named, for example "+20 autostart target is in a
user-writable location". Every term appears in `score_breakdown`.

**Incident:** each rule counts once, at its highest-scoring alert. Score =
top rule + 20% of each further distinct rule, capped at 100. Alerts marked
`false_positive` contribute 0. Repeated events and several alerts from the
same rule are not independent evidence. Incident severity is the highest
severity among active alerts.

## Correlation

An alert joins a non-closed incident on the same host if they share an entity
and the incident's activity window (±60 min, configurable) overlaps the alert.
Entities:

- `process:guid:{host}:{ProcessGuid}`: PID-reuse safe
- `process:pid:{host}:{pid}:{start}`: Security 4688 processes (no GUID)
- the acting process's parent: links parent and child activity
- `file:{host}:{path}`: links a dropped file, its execution and its autostart entry

If an alert matches several incidents, it joins the most recent one. The
others are noted in its uncertainty list, not merged automatically.

## Process tracking

- **PID reuse:** identity is the ProcessGuid, or PID plus creation time.
- **Out-of-order delivery:** a process seen first through a network event is
  created with `creation_observed=false`, and its creation event fills it in
  later. `first_seen`/`last_seen` use min/max.
- **Missing events:** unknown fields stay NULL. A parent known only from its
  child's event has no `start_time`.
- **Conflicting evidence:** the first value wins. Later disagreements are
  listed in `conflicts`.
- **Termination:** Sysmon 5 sets `end_time`. PID lookups respect process
  lifetimes.

## Configuration

`server/config/detection/detection.json` (see `detection.example.json`):
per-rule `enabled`/`thresholds`, an `allowlist` (`images`, `sha256`),
`incident_window_minutes` and `max_evidence_per_alert`. The API reloads the
file when it changes. The collector reads it at start.

## Capability matrix

`GET /api/v1/detection/capabilities` lists 24 techniques. For each it gives
the design visibility (`observable`, `partially_observable`, `not_observable`)
and the **effective** visibility on this host given current sensor health. If
Sysmon isn't installed, every Sysmon-based technique reports
`not_observable`, with the reason.

Key gaps, stated plainly:

- **Keylogging** via low-level hooks (WH_KEYBOARD_LL), GetAsyncKeyState polling
  or Raw Input is **not observable** with Sysmon or the event log. Only
  DLL-based global hooks leave a trace (the DLL loaded into many processes).
- Screen capture, audio capture and kernel rootkits are not observable.
- Clipboard is deliberately not collected.
- Signed vulnerable drivers (BYOVD) aren't flagged: no hash list is configured.
- Scheduled tasks and log clearing are stored but have no dedicated rule yet.

## Tuning from live telemetry (2026-10-24)

All changes are narrow, grounded in what the technique requires, and covered
by a regression test. Before/after numbers are in `docs/operations.md`.

| Rule | Version | Change | False-positive source |
|---|---|---|---|
| KG-INJ-002 | v3 | Requires write, operation or create-thread rights; skips same-program siblings and parent→child handles; one alert per program pair | JIT runtimes (Claude, VS Code, pwsh, PowerToys, Lenovo Vantage) |
| KG-SPY-001 | v3 | Counts distinct *programs* outside the DLL's own installation (`min_programs`); skips .NET NGen native images | Git's MSYS2 DLLs; `C:\Windows\assembly\NativeImages_*` |
| KG-FILE-001 | v2 | Skips `__PSScriptPolicyTest_*.ps1/psm1` only when written by PowerShell | PowerShell AppLocker probe at every start |
| KG-INJ-001 | v2 | Skips module-backed threads into the same program; winlogon/dwm added to system sources | Electron child threads; winlogon/dwm → csrss |

## Known limitations

- Rules have been validated against synthetic Sysmon events and real System
  7045 events only. Sysmon wasn't installed on the development host, so
  false-positive rates on real Sysmon telemetry are **unmeasured**.
- Detection throughput in a worst-case benchmark (20k events from a single
  process, most of them firing rules) is about 210 events/s, against about
  1,050 events/s for ingestion alone. Realistic mixed workloads haven't been
  measured yet (Phase 5).
- KG-SPY-002 links up to 25 contributing evidence events. Later contributing
  evidence beyond that doesn't refresh its observations.
- An alert already marked `false_positive` stays in that status when the
  same subject fires again. Its occurrence count still increases.
- Analyst actions are attributed to `local` until authentication exists.
