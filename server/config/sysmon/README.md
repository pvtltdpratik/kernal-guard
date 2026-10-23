# Sysmon for KernelGuard

KernelGuard reads Sysmon events from `Microsoft-Windows-Sysmon/Operational`.
It never installs or configures Sysmon itself; installing it is an explicit
administrator action.

## Install with the setup script (recommended)

From an **elevated** PowerShell at the repository root:

```powershell
powershell -ExecutionPolicy Bypass -File .\server\scripts\setup-sysmon.ps1 -GrantEventLogRead
```

The script checks the Microsoft signature, installs Sysmon (or updates its
config if it's already installed), verifies both services and the event
channel, and optionally adds your account to *Event Log Readers*. Sign out
and back in afterwards so the group membership takes effect.

## Install manually (elevated PowerShell)

1. Download Sysmon from Microsoft Sysinternals:
   https://learn.microsoft.com/sysinternals/downloads/sysmon
   Verify the signature (`Get-AuthenticodeSignature .\Sysmon64.exe` should
   show `Valid`, signed by Microsoft).
2. Review `kernelguard-sysmon.xml` and adjust it for the host.
3. Install with the config:

   ```powershell
   .\Sysmon64.exe -accepteula -i C:\path\to\kernelguard\server\config\sysmon\kernelguard-sysmon.xml
   ```

4. Later config changes: `.\Sysmon64.exe -c kernelguard-sysmon.xml`
5. Check what's active: `.\Sysmon64.exe -c`

## Reading the channel

By default only Administrators and SYSTEM can read the Sysmon channel. Run
the collector elevated, or grant a dedicated account read access through the
`Event Log Readers` group (sign out and back in afterwards).

## Status of this config

- Schema 4.91 (Sysmon 15.22). Every rule element and field name was checked
  against `Sysmon64.exe -s` output from 15.22, and so was every field the
  KernelGuard normaliser reads. **The config hasn't yet been loaded into a
  running Sysmon**, so `Sysmon64.exe -c` validation and event volume are still
  unverified.
- Network connections and DNS queries are logged without filtering. Expect
  high volume from browsers. KernelGuard's retention settings bound storage,
  but tune exclusions once you see real traffic.
- Sysmon does not record keystrokes, and it cannot observe every keyboard-hook
  technique (for example, `SetWindowsHookEx` calls aren't logged). See the
  capability matrix (Phase 3) for what is and isn't visible.
