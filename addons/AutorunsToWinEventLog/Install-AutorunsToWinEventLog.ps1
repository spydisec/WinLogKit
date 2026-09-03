<#
.SYNOPSIS
    Installs, checks or removes the AutorunsToWinEventLog add-on: a daily
    scheduled task that writes every Sysinternals Autoruns entry into a
    dedicated "Autoruns" event log for collection by WEF/AMA.

.DESCRIPTION
    What install does (all idempotent, rerun freely):
      1. Creates the install folder under Program Files (admin-write-only,
         so a SYSTEM task never executes from a user-writable path).
      2. Puts autorunsc there: from -AutorunscPath (a copy you already have)
         or with -Download from live.sysinternals.com over HTTPS. Either
         way the binary's Authenticode signature must be valid and signed
         by Microsoft or the install stops and removes it.
      3. Copies AutorunsToWinEventLog.ps1 (the payload) alongside it.
      4. Creates the "Autoruns" event log and its event source, sized to
         -LogMaxMB (default 128 MB) with overwrite-as-needed retention.
      5. Registers the scheduled task "AutorunsToWinEventLog": daily at
         -DailyAt (default 01:00), as SYSTEM, 60-minute limit, runs when
         next available if the time was missed.

    Nothing here touches the kit's own settings, audit policy or any other
    channel; the add-on is self-contained and -Uninstall removes it cleanly.

    Origin: a rewrite of Palantir's AutorunsToWinEventLog installer (MIT,
    Copyright (c) 2018 Palantir Technologies Inc., see LICENSE-Palantir.md).
    Differences from the original: signature verification of the download,
    Program Files kept but with a quoted path instead of the PROGRA~1 short
    name, the event log created and sized at install time rather than on
    first run, -WhatIf, -Status and -Uninstall, and a -RunNow for immediate
    verification.

    Requires: local Administrator. Windows PowerShell 5.1 or PowerShell 7.
    Sysinternals tools carry their own licence terms (the installer passes
    -accepteula on your behalf when the task runs; read them first:
    https://learn.microsoft.com/sysinternals/license-terms).

.PARAMETER Download
    Fetch autorunsc from https://live.sysinternals.com. Explicit opt-in, as
    with the kit's WELA download - nothing is fetched unless asked.

.PARAMETER AutorunscPath
    Use this copy of autorunsc64.exe / autorunsc.exe instead of downloading
    (air-gapped estates: bring the file from the Sysinternals Suite).

.PARAMETER DailyAt
    Daily run time, 24-hour HH:mm. Default 01:00.

.PARAMETER LogMaxMB
    Maximum size of the Autoruns event log in MB. Default 128 (the kit's
    standard channel size). Observed on a Windows 11 workstation with
    autorunsc 14.3: one run = ~1,640 entries = ~4 MB of event log, so
    128 MB holds about a month locally; central collection is the real
    retention.

.PARAMETER InstallDir
    Override the install folder. Default: %ProgramFiles%\WinLogKit\AutorunsToWinEventLog.

.PARAMETER RunNow
    After installing, start the task immediately so you can verify with
    -Status (or Get-WinEvent) within a couple of minutes.

.PARAMETER Status
    Report only: task state and last result, log size and record count,
    the most recent run summary (ID 100) and any failure (ID 101) in the
    last 7 days, and the installed autorunsc version. Changes nothing.

.PARAMETER Uninstall
    Remove the task, the event source, the install folder and its files.
    The Autoruns log itself is kept (it holds evidence) unless -RemoveLog.

.PARAMETER RemoveLog
    With -Uninstall: also delete the Autoruns event log and its data.

.EXAMPLE
    .\Install-AutorunsToWinEventLog.ps1 -Download -WhatIf
    Shows every step without doing any of it.

.EXAMPLE
    .\Install-AutorunsToWinEventLog.ps1 -Download -RunNow
    Installs, then runs the first collection immediately.

.EXAMPLE
    .\Install-AutorunsToWinEventLog.ps1 -AutorunscPath D:\SysinternalsSuite\autorunsc64.exe
    Air-gapped install from a local copy.

.EXAMPLE
    .\Install-AutorunsToWinEventLog.ps1 -Status
#>
[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')] [switch]$Download,
    [Parameter(ParameterSetName = 'Install')] [string]$AutorunscPath,
    [Parameter(ParameterSetName = 'Install')] [ValidatePattern('^(?:[01][0-9]|2[0-3]):[0-5][0-9]$')] [string]$DailyAt = '01:00',
    [Parameter(ParameterSetName = 'Install')] [ValidateRange(8, 4096)] [int]$LogMaxMB = 128,
    [Parameter(ParameterSetName = 'Install')] [switch]$RunNow,
    [Parameter(ParameterSetName = 'Status')]  [switch]$Status,
    [Parameter(ParameterSetName = 'Uninstall')] [switch]$Uninstall,
    [Parameter(ParameterSetName = 'Uninstall')] [switch]$RemoveLog,
    [string]$InstallDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$taskName = 'AutorunsToWinEventLog'
$logName  = 'Autoruns'
$source   = 'AutorunsToWinEventLog'
$exeName  = if ([Environment]::Is64BitOperatingSystem) { 'autorunsc64.exe' } else { 'autorunsc.exe' }
$downloadUri = "https://live.sysinternals.com/$exeName"
if ([string]::IsNullOrEmpty($InstallDir)) { $InstallDir = Join-Path (Join-Path $env:ProgramFiles 'WinLogKit') 'AutorunsToWinEventLog' }
$exePath    = Join-Path $InstallDir $exeName
$runnerSrc  = Join-Path $PSScriptRoot 'AutorunsToWinEventLog.ps1'
$runnerDest = Join-Path $InstallDir 'AutorunsToWinEventLog.ps1'

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ---- Status ----------------------------------------------------------------
if ($Status) {
    Write-Host "AutorunsToWinEventLog status on $env:COMPUTERNAME" -ForegroundColor Cyan
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -eq $task) {
        Write-Host "  Task        : not installed" -ForegroundColor Yellow
    } else {
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        Write-Host "  Task        : $($task.State); last run $($info.LastRunTime), result 0x$('{0:X}' -f $info.LastTaskResult); next run $($info.NextRunTime)"
    }
    if (Test-Path $exePath) {
        Write-Host "  autorunsc   : $((Get-Item $exePath).VersionInfo.ProductVersion) at $exePath"
    } else {
        Write-Host "  autorunsc   : missing ($exePath)" -ForegroundColor Yellow
    }
    $logInfo = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if ($null -eq $logInfo) {
        Write-Host "  Event log   : '$logName' does not exist" -ForegroundColor Yellow
    } else {
        Write-Host "  Event log   : $($logInfo.RecordCount) records, $([math]::Round($logInfo.FileSize/1MB, 1)) MB used of $([math]::Round($logInfo.MaximumSizeInBytes/1MB)) MB, mode $($logInfo.LogMode)"
        $since = (Get-Date).AddDays(-7)
        $last100 = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = 100; StartTime = $since } -MaxEvents 1 -ErrorAction SilentlyContinue
        $last101 = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = 101; StartTime = $since } -MaxEvents 1 -ErrorAction SilentlyContinue
        if ($null -ne $last100) { Write-Host "  Last summary: $($last100.TimeCreated)`n    $($last100.Message -replace "`r`n", "`n    ")" }
        else { Write-Host "  Last summary: no run summary (ID 100) in the last 7 days" -ForegroundColor Yellow }
        if ($null -ne $last101) { Write-Host "  Last FAILURE: $($last101.TimeCreated)`n    $($last101.Message -replace "`r`n", "`n    ")" -ForegroundColor Red }
    }
    exit 0
}

if (-not $isAdmin) { Write-Error 'Run from an elevated prompt (local Administrator).'; exit 1 }

# ---- Uninstall -------------------------------------------------------------
if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        if ($PSCmdlet.ShouldProcess("scheduled task '$taskName'", 'unregister')) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Host "Removed scheduled task '$taskName'."
        }
    } else { Write-Host "Scheduled task '$taskName' not present." }

    if ([System.Diagnostics.EventLog]::SourceExists($source)) {
        if ($PSCmdlet.ShouldProcess("event source '$source'", 'delete')) {
            [System.Diagnostics.EventLog]::DeleteEventSource($source)
            Write-Host "Removed event source '$source'."
        }
    }
    if ($RemoveLog -and [System.Diagnostics.EventLog]::Exists($logName)) {
        if ($PSCmdlet.ShouldProcess("event log '$logName' and all its records", 'delete')) {
            [System.Diagnostics.EventLog]::Delete($logName)
            Write-Host "Deleted event log '$logName'."
        }
    } elseif ([System.Diagnostics.EventLog]::Exists($logName)) {
        Write-Host "Event log '$logName' kept (use -RemoveLog to delete it and its records)."
    }
    if (Test-Path $InstallDir) {
        if ($PSCmdlet.ShouldProcess($InstallDir, 'remove folder')) {
            Remove-Item $InstallDir -Recurse -Force
            Write-Host "Removed $InstallDir."
        }
    }
    exit 0
}

# ---- Install ---------------------------------------------------------------
if (-not (Test-Path $runnerSrc)) { Write-Error "Payload script not found next to the installer: $runnerSrc"; exit 1 }

# 1. Folder. Program Files is admin-write-only by default: a task running as
#    SYSTEM must never execute a script or binary from a location a standard
#    user can replace. Two checks enforce that for a custom -InstallDir:
#      a) it must be a local path under Program Files, Program Files (x86)
#         or the Windows folder - roots whose every ancestor is admin-only
#         by OS design, so nobody can delete and recreate the folder from
#         above (no UNC paths, no reparse points);
#      b) the folder's own DACL may grant write-class rights only to
#         SYSTEM, Administrators, TrustedInstaller/service SIDs and
#         CREATOR OWNER. Anyone else with a write bit refuses the install.
$trustedRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:SystemRoot) | Where-Object { -not [string]::IsNullOrEmpty($_) }
$installFull = [System.IO.Path]::GetFullPath($InstallDir)
if ($installFull.StartsWith('\\')) { Write-Error "InstallDir must be a local path, not UNC: $installFull"; exit 1 }
$underTrustedRoot = $false
foreach ($root in $trustedRoots) {
    $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
    if ($installFull.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) { $underTrustedRoot = $true }
}
if (-not $underTrustedRoot) {
    Write-Error "InstallDir must sit under Program Files or the Windows folder (admin-only ancestors): $installFull"
    exit 1
}
# Walk from the trusted root down to the leaf: any existing segment that is
# a reparse point (junction/symlink) could redirect to an untrusted location.
$probe = $installFull.TrimEnd('\')
while ($probe -and (Split-Path $probe -Parent)) {
    if ((Test-Path $probe) -and ((Get-Item $probe -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        Write-Error "InstallDir path contains a reparse point (junction or symlink): $probe"; exit 1
    }
    $probe = Split-Path $probe -Parent
}
$InstallDir = $installFull
if (-not (Test-Path $InstallDir)) {
    if ($PSCmdlet.ShouldProcess($InstallDir, 'create folder')) { New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null }
}
if (Test-Path $InstallDir) {
    $trustedWriterSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0')   # SYSTEM, BUILTIN\Administrators, CREATOR OWNER
    # Atomic write-class bits only. Composite rights (Modify, FullControl)
    # contain these bits and are caught; ReadAndExecute shares none of them.
    $writeMask = [System.Security.AccessControl.FileSystemRights]'CreateFiles, CreateDirectories, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $acl = Get-Acl $InstallDir
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (($ace.FileSystemRights -band $writeMask) -eq 0) { continue }
        $sid = try { $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { '' }
        $trusted = ($trustedWriterSids -contains $sid) -or $sid.StartsWith('S-1-5-80-')   # S-1-5-80-*: service SIDs incl. TrustedInstaller
        if (-not $trusted) {
            Write-Error ("Install folder $InstallDir grants $($ace.IdentityReference) '$($ace.FileSystemRights)'. " +
                         'A SYSTEM task must not run from a folder anyone but administrators can write to. Use the default (Program Files) or an admin-only folder.')
            exit 1
        }
    }
}

# 2. Binary: local copy, existing install, or explicit download.
if (-not [string]::IsNullOrEmpty($AutorunscPath)) {
    if (-not (Test-Path $AutorunscPath)) { Write-Error "AutorunscPath not found: $AutorunscPath"; exit 1 }
    if ($PSCmdlet.ShouldProcess($exePath, "copy from $AutorunscPath")) { Copy-Item $AutorunscPath $exePath -Force }
} elseif (Test-Path $exePath) {
    Write-Host "autorunsc already present: $((Get-Item $exePath).VersionInfo.ProductVersion) (pass -AutorunscPath or delete it to replace)."
} elseif ($Download) {
    if ($PSCmdlet.ShouldProcess($exePath, "download from $downloadUri")) {
        # Same TLS handling as the kit's WELA download: only ADD TLS 1.2 when
        # a legacy explicit protocol set lacks it; never remove anything.
        $currentProtocols = [Net.ServicePointManager]::SecurityProtocol
        if ($currentProtocols -ne [Net.SecurityProtocolType]::SystemDefault -and <# DevSkim: ignore DS440020 - SystemDefault check preserves OS negotiation #>
            -not ($currentProtocols -band [Net.SecurityProtocolType]::Tls12)) {  # DevSkim: ignore DS440001,DS440020 - capability probe, not a protocol pin
            [Net.ServicePointManager]::SecurityProtocol = $currentProtocols -bor [Net.SecurityProtocolType]::Tls12  # DevSkim: ignore DS440001,DS440020 - additive minimum-version fix, never downgrades
        }
        Write-Host "Downloading $downloadUri ..."
        Invoke-WebRequest -Uri $downloadUri -OutFile $exePath -UseBasicParsing
    }
} else {
    Write-Error "autorunsc not present at $exePath. Pass -Download (fetch from live.sysinternals.com) or -AutorunscPath <local copy>."
    exit 1
}

# 2b. Trust check. Whatever the origin, the binary must carry a valid
#     Microsoft Authenticode signature, or it is removed and we stop.
if (Test-Path $exePath) {
    $sig = Get-AuthenticodeSignature $exePath
    $signer = if ($null -ne $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    if ($sig.Status -ne 'Valid' -or $signer -notmatch 'O=Microsoft Corporation') {
        $removed = 'File would be removed'
        if ($PSCmdlet.ShouldProcess($exePath, 'remove after failed signature check')) {
            Remove-Item $exePath -Force -ErrorAction SilentlyContinue
            $removed = 'File removed'
        }
        Write-Error "autorunsc signature check failed (status $($sig.Status), signer '$signer'). $removed; nothing installed."
        exit 1
    }
    Write-Host "autorunsc $((Get-Item $exePath).VersionInfo.ProductVersion): signature Valid, signer Microsoft Corporation."
}

# 3. Payload script.
if ($PSCmdlet.ShouldProcess($runnerDest, 'copy payload script')) { Copy-Item $runnerSrc $runnerDest -Force }

# 4. Event log + source, sized here so the first run cannot fill a default
#    512 KB classic log. Overwrite-as-needed matches the kit's never-do rule
#    on "do not overwrite" retention.
if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
    if ($PSCmdlet.ShouldProcess("event log '$logName' with source '$source'", 'create')) {
        [System.Diagnostics.EventLog]::CreateEventSource($source, $logName)
        Write-Host "Created event log '$logName' (source '$source')."
    }
}
if ([System.Diagnostics.EventLog]::Exists($logName)) {
    if ($PSCmdlet.ShouldProcess("event log '$logName'", "set maximum size ${LogMaxMB} MB, overwrite as needed")) {
        $lg = New-Object System.Diagnostics.EventLog($logName)
        try {
            $lg.MaximumKilobytes = $LogMaxMB * 1024
            $lg.ModifyOverflowPolicy([System.Diagnostics.OverflowAction]::OverwriteAsNeeded, 0)
        } finally { $lg.Dispose() }
    }
}

# 5. Scheduled task. powershell.exe (always present) runs the payload; the
#    payload itself is PowerShell 7 clean, so swap in pwsh.exe if you prefer.
$action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$runnerDest`""
$trigger   = New-ScheduledTaskTrigger -Daily -At $DailyAt
$principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest -LogonType ServiceAccount
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
if ($PSCmdlet.ShouldProcess("scheduled task '$taskName'", "register (daily at $DailyAt as SYSTEM)")) {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Host "Registered scheduled task '$taskName' (daily at $DailyAt, SYSTEM)."
}

if ($RunNow -and $PSCmdlet.ShouldProcess("scheduled task '$taskName'", 'start now')) {
    Start-ScheduledTask -TaskName $taskName
    Write-Host "Started. Check in a minute or two with: .\Install-AutorunsToWinEventLog.ps1 -Status"
}
Write-Host 'Done. Verify any time with -Status; collect centrally by adding the Autoruns channel to your WEF subscription or DCR.' -ForegroundColor Green
exit 0
