#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs (or reconfigures) Sysmon with the KernelGuard configuration and,
    optionally, grants an account read access to event logs.

.DESCRIPTION
    Run from an elevated PowerShell:
        powershell -ExecutionPolicy Bypass -File .\server\scripts\setup-sysmon.ps1 -GrantEventLogRead

    Steps (each verified, each reported):
      1. Locate Sysmon64.exe (PATH, then C:\Program Files\sysmon) and require a
         valid Microsoft Authenticode signature.
      2. Install Sysmon with config\sysmon\kernelguard-sysmon.xml, or update the
         configuration if Sysmon is already installed.
      3. Verify the Sysmon64 / SysmonDrv services are running and the
         Microsoft-Windows-Sysmon/Operational channel exists.
      4. With -GrantEventLogRead: add the account to the built-in
         "Event Log Readers" group (read-only access to event logs, including
         Security). Sign out and back in afterwards for it to take effect.

    The script never uninstalls anything and makes no other changes.
#>
[CmdletBinding()]
param(
    [string]$SysmonPath,
    [string]$ConfigPath = (Join-Path $PSScriptRoot "..\config\sysmon\kernelguard-sysmon.xml"),
    [switch]$GrantEventLogRead,
    [string]$Account = "$env:USERDOMAIN\$env:USERNAME"
)

$ErrorActionPreference = "Stop"
$failed = $false

function Write-Step([string]$Text) { Write-Host "`n== $Text" -ForegroundColor Cyan }
function Write-Ok([string]$Text) { Write-Host "   OK   $Text" -ForegroundColor Green }
function Write-Fail([string]$Text) { Write-Host "   FAIL $Text" -ForegroundColor Red; $script:failed = $true }

# 1. Locate and verify the binary --------------------------------------------
Write-Step "Locating Sysmon64.exe"
if (-not $SysmonPath) {
    $cmd = Get-Command Sysmon64.exe -ErrorAction SilentlyContinue
    $SysmonPath = if ($cmd) { $cmd.Source } else { "C:\Program Files\sysmon\Sysmon64.exe" }
}
if (-not (Test-Path $SysmonPath)) { Write-Fail "Not found: $SysmonPath (pass -SysmonPath)"; exit 1 }
$sig = Get-AuthenticodeSignature $SysmonPath
$version = (Get-Item $SysmonPath).VersionInfo.FileVersion
if ($sig.Status -ne "Valid" -or $sig.SignerCertificate.Subject -notmatch "O=Microsoft Corporation") {
    Write-Fail "Signature check failed for $SysmonPath ($($sig.Status), $($sig.SignerCertificate.Subject))"
    exit 1
}
Write-Ok "$SysmonPath  version $version  signed by Microsoft"

$ConfigPath = (Resolve-Path $ConfigPath).Path
Write-Ok "Config: $ConfigPath"

# 2. Install or update ----------------------------------------------------------
$installed = [bool](Get-Service -Name Sysmon64 -ErrorAction SilentlyContinue)
if ($installed) {
    Write-Step "Sysmon already installed; applying KernelGuard configuration"
    & $SysmonPath -accepteula -c $ConfigPath
} else {
    Write-Step "Installing Sysmon with KernelGuard configuration"
    & $SysmonPath -accepteula -i $ConfigPath
}
if ($LASTEXITCODE -ne 0) { Write-Fail "Sysmon exited with code $LASTEXITCODE (see its output above)" } else { Write-Ok "Sysmon exit code 0" }

# 3. Verify ---------------------------------------------------------------------
Write-Step "Verifying services and event channel"
foreach ($name in "Sysmon64", "SysmonDrv") {
    $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") { Write-Ok "$name is Running" } else { Write-Fail "$name is $(if ($svc) { $svc.Status } else { 'not installed' })" }
}
try {
    $log = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"
    Write-Ok "Channel exists ($($log.RecordCount) records, max $([math]::Round($log.MaximumSizeInBytes / 1MB)) MB)"
    if ($log.MaximumSizeInBytes -lt 64MB) {
        Write-Host "   NOTE Channel is small; consider: wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456" -ForegroundColor Yellow
    }
} catch { Write-Fail "Channel Microsoft-Windows-Sysmon/Operational not found" }

# 4. Read access ------------------------------------------------------------------
if ($GrantEventLogRead) {
    Write-Step "Granting $Account read access to event logs (Event Log Readers)"
    $members = Get-LocalGroupMember -Group "Event Log Readers" | ForEach-Object { $_.Name }
    if ($members -contains $Account) {
        Write-Ok "$Account is already a member"
    } else {
        Add-LocalGroupMember -Group "Event Log Readers" -Member $Account
        Write-Ok "$Account added. SIGN OUT AND BACK IN for this to take effect."
    }
}

Write-Host ""
if ($failed) { Write-Host "Setup finished WITH ERRORS. Send the output above for diagnosis." -ForegroundColor Red; exit 1 }
Write-Host "Setup complete." -ForegroundColor Green
