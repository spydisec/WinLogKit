<#
.SYNOPSIS
    Runs Sysinternals autorunsc and writes every autostart entry it finds to
    the "Autoruns" Windows event log, one event per entry (Event ID 1), plus
    a run summary (ID 100) or a failure record (ID 101).

.DESCRIPTION
    This is the scheduled-task payload of the AutorunsToWinEventLog add-on.
    Install-AutorunsToWinEventLog.ps1 puts it in place and schedules it; you
    normally never run it by hand except to test.

    Why it exists: native Windows auditing cannot see registry autostart
    locations (Run keys, IFEO, Winlogon, services, scheduled tasks and the
    dozens of others) without per-key SACLs. Autoruns enumerates them all.
    Writing the result into an event log turns a point-in-time tool into a
    daily telemetry feed that rides the same WEF/AMA pipeline as everything
    else this kit configures, so persistence hunting happens in the SIEM
    rather than on the box.

    Origin: a rewrite of Palantir's AutorunsToWinEventLog (MIT licensed,
    Copyright (c) 2018 Palantir Technologies Inc., see LICENSE-Palantir.md).
    Deliberate differences from the original, each with a reason:
      - No VirusTotal lookups (-v / -vt). They need internet from every host,
        slow the run, and the original's flags submitted hashes to a third
        party by default. Hashes (-h) and signature verification (-s) are
        kept, so VT can be done SIEM-side if wanted.
      - autorunsc writes its CSV with -o instead of stdout redirection, and
        the file is read as UTF-8 (what autorunsc 14.x writes). The original
        read the file with the default ANSI code page, mangling any
        non-ASCII path or description.
      - Every CSV column is written dynamically, so new Autoruns columns
        (PESHA-256, IMP, ...) appear without code changes. The message
        layout is the original's Format-List style ("Key : Value" lines)
        so existing parsers keep working.
      - No -m (hide Microsoft-signed entries): attackers abuse Microsoft-
        signed binaries for persistence (Huntress "evading autoruns"), and
        the original repo's issue #11 reached the same conclusion.
      - The original's second job (local group membership, Event ID 2) is
        not carried over: the kit already covers group changes natively
        (4732/4733/4756...) and mixing two feeds in one log made parsing
        ambiguous.
      - Adds a run-summary event (ID 100) and a failure event (ID 101), so a
        SIEM can alert when a host stops reporting or the run breaks -
        "onboarded" means health-monitored, not just configured.
      - Uses the .NET System.Diagnostics.EventLog API rather than the
        Write-EventLog cmdlet, which does not exist in PowerShell 7.

    Event IDs in the Autoruns log:
        1   one autostart entry (message = all autorunsc columns)
        100 run summary: entry count, duration, autorunsc version
        101 run failure: the error text

    Requires: Windows PowerShell 5.1 or PowerShell 7. Writing needs the
    "Autoruns" log and its event source to exist (the installer creates
    them) and the rights to write to it (the scheduled task runs as SYSTEM).

.PARAMETER AutorunscPath
    Path to autorunsc64.exe (or autorunsc.exe on 32-bit Windows). Default:
    the copy sitting next to this script, which is where the installer puts
    it.

.PARAMETER InputCsv
    Test hook: parse an existing autorunsc CSV instead of running autorunsc.
    Used by the kit self-checks with a fixture file; also handy for looking
    at what a run would write from another machine's output.

.PARAMETER LogName
    Event log to write to. Default "Autoruns" (matches the original, so any
    subscription or detection content written for it keeps working).

.PARAMETER Source
    Event source name. Default "AutorunsToWinEventLog" (same reason).

.EXAMPLE
    .\AutorunsToWinEventLog.ps1 -WhatIf
    Runs autorunsc, parses the result and reports what would be written.
    Writes nothing. Does not need the event log to exist.

.EXAMPLE
    .\AutorunsToWinEventLog.ps1 -InputCsv .\tests\fixtures\autoruns-sample.csv -WhatIf
    Parses a fixture instead of running autorunsc (no binary needed).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$AutorunscPath,
    [string]$InputCsv,
    [string]$LogName = 'Autoruns',
    [string]$Source = 'AutorunsToWinEventLog'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Classic event log messages cap out around 31,839 characters. Autoruns rows
# are ~1 KB, so this never triggers in practice; it is a guard, not a feature.
$maxMessageChars = 31000

# $PSScriptRoot is not reliably available in param defaults under -File, so
# the default binary path is resolved here.
if ([string]::IsNullOrEmpty($AutorunscPath) -and [string]::IsNullOrEmpty($InputCsv)) {
    $exeName = if ([Environment]::Is64BitOperatingSystem) { 'autorunsc64.exe' } else { 'autorunsc.exe' }
    $AutorunscPath = Join-Path $PSScriptRoot $exeName
}

function Write-AutorunsEvent {
    # Single choke point for event writes. Uses the .NET API so the same code
    # runs on Windows PowerShell 5.1 and PowerShell 7 (no Write-EventLog).
    param(
        [System.Diagnostics.EventLog]$Log,
        [int]$EventId,
        [System.Diagnostics.EventLogEntryType]$Type,
        [string]$Message
    )
    if ($Message.Length -gt $maxMessageChars) { $Message = $Message.Substring(0, $maxMessageChars) + "`r`n[truncated]" }
    $Log.WriteEntry($Message, $Type, $EventId)
}

function ConvertTo-EntryMessage {
    # One "Key : Value" line per CSV column, in CSV column order, keys padded
    # to the widest name so the block lines up like Format-List output. This
    # is the original tool's message shape; keeping it means anything that
    # already parses Autoruns events (Splunk extractions, Sigma-derived
    # rules) keeps parsing.
    param([psobject]$Row, [int]$KeyWidth)
    $lines = foreach ($p in $Row.PSObject.Properties) {
        # A quoted CSV field can legally contain line breaks (a launch
        # string, say). Escape them so every line of the message still
        # starts with a key and parsers never see a stray continuation line.
        $value = [string]$p.Value -replace "`r", '\r' -replace "`n", '\n'
        ('{0,-' + $KeyWidth + '} : {1}') -f $p.Name, $value
    }
    return ($lines -join "`r`n")
}

$started = Get-Date
$log = $null
$csvPath = $null
$ownCsv = $false

try {
    # ---- 1. Get a CSV: run autorunsc, or take the one we were given ----------
    if (-not [string]::IsNullOrEmpty($InputCsv)) {
        if (-not (Test-Path $InputCsv)) { throw "InputCsv not found: $InputCsv" }
        $csvPath = (Resolve-Path $InputCsv).Path
        $autorunscVersion = 'n/a (InputCsv)'
    } else {
        if (-not (Test-Path $AutorunscPath)) {
            throw "autorunsc not found at $AutorunscPath - run Install-AutorunsToWinEventLog.ps1 (with -Download or -AutorunscPath) first."
        }
        $autorunscVersion = (Get-Item $AutorunscPath).VersionInfo.ProductVersion
        # SYSTEM's temp is C:\Windows\Temp; an interactive test uses the user's.
        $csvPath = Join-Path ([System.IO.Path]::GetTempPath()) ("autoruns-{0}-{1}.csv" -f $PID, (Get-Random))
        $ownCsv = $true

        # autorunsc flags:
        #   -nobanner    no banner text (it would corrupt the CSV)
        #   -accepteula  never block on the EULA dialog under SYSTEM
        #   -a *         every autostart category
        #   -c           CSV output
        #   -h           file hashes (MD5/SHA-1/SHA-256/PE hashes/IMP)
        #   -s           verify digital signatures ("(Verified) Microsoft Windows")
        #   -o <file>    write the CSV to a file (UTF-8 in 14.x)
        #   *            scan all user profiles, not just the current one
        # The original noted that Start-Process -Wait misbehaves from scheduled
        # tasks; -PassThru + WaitForExit() is the reliable form.
        $argList = @('-nobanner', '-accepteula', '-a', '*', '-c', '-h', '-s', '-o', "`"$csvPath`"", '*')
        $proc = Start-Process -FilePath $AutorunscPath -ArgumentList $argList -WindowStyle Hidden -PassThru
        # A full scan takes about a minute; 30 minutes means something is
        # wedged (the scheduled task's own limit is 60). Kill and report
        # rather than hang an interactive run forever.
        if (-not $proc.WaitForExit(30 * 60 * 1000)) {
            try { $proc.Kill() } catch { Write-Verbose "kill failed: $($_.Exception.Message)" }
            throw 'autorunsc did not finish within 30 minutes; process killed, output discarded'
        }
        # autorunsc 14.3 exits 0 on success and non-zero (-1 observed) on
        # error. A partial CSV after a mid-scan failure must not be written as
        # a healthy run: fail here so the SIEM sees an ID 101, not an ID 100.
        if ($proc.ExitCode -ne 0) { throw "autorunsc exited with code $($proc.ExitCode); output discarded" }
        if (-not (Test-Path $csvPath)) { throw 'autorunsc exited 0 but produced no output file' }
    }

    # ---- 2. Parse ------------------------------------------------------------
    # autorunsc 14.3 writes the -o file as UTF-8 without a BOM (observed; the
    # original tool read it with the ANSI code page and mangled non-ASCII
    # paths). Sniff for a UTF-16 BOM anyway so a future version that changes
    # its output encoding still parses.
    $fs = [System.IO.File]::OpenRead($csvPath)
    try { $bom = New-Object byte[] 2; $bomLen = $fs.Read($bom, 0, 2) } finally { $fs.Dispose() }
    $csvEncoding = 'UTF8'
    if ($bomLen -ge 2) {
        if ($bom[0] -eq 0xFF -and $bom[1] -eq 0xFE) { $csvEncoding = 'Unicode' }
        elseif ($bom[0] -eq 0xFE -and $bom[1] -eq 0xFF) { $csvEncoding = 'BigEndianUnicode' }
    }
    $rows = @(Import-Csv -Path $csvPath -Encoding $csvEncoding)
    if ($rows.Count -eq 0) { throw "CSV at $csvPath contained no rows" }
    $columns = @($rows[0].PSObject.Properties.Name)
    if ($columns -notcontains 'Entry Location') {
        throw "CSV does not look like autorunsc output (no 'Entry Location' column). Columns: $($columns -join ', ')"
    }
    $keyWidth = ($columns | Measure-Object -Property Length -Maximum).Maximum

    # ---- 3. Write ------------------------------------------------------------
    if (-not $PSCmdlet.ShouldProcess("event log '$LogName' (source '$Source')", "write $($rows.Count) autostart entries")) {
        # -WhatIf: show the shape of what would be written and stop. No event
        # log access at all, so this works on a machine without the add-on.
        Write-Output "WhatIf: would write $($rows.Count) entries to event log '$LogName' as Event ID 1 (source '$Source'); columns: $($columns -join ', ')"
        Write-Output 'WhatIf: first entry as it would appear in the event message:'
        Write-Output (ConvertTo-EntryMessage -Row $rows[0] -KeyWidth $keyWidth)
        return
    }

    if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
        throw "Event source '$Source' does not exist - run Install-AutorunsToWinEventLog.ps1 first."
    }
    $log = New-Object System.Diagnostics.EventLog($LogName)
    $log.Source = $Source

    $written = 0
    foreach ($row in $rows) {
        Write-AutorunsEvent -Log $log -EventId 1 -Type Information -Message (ConvertTo-EntryMessage -Row $row -KeyWidth $keyWidth)
        $written++
    }

    $elapsed = [int]((Get-Date) - $started).TotalSeconds
    $summary = "AutorunsToWinEventLog run complete.`r`nEntries written : $written`r`nDuration (s)    : $elapsed`r`nautorunsc       : $autorunscVersion`r`nHost            : $env:COMPUTERNAME"
    Write-AutorunsEvent -Log $log -EventId 100 -Type Information -Message $summary
    Write-Host "Wrote $written autostart entries to '$LogName' in ${elapsed}s (summary event 100)."
}
catch {
    $err = $_.Exception.Message
    # Best effort: record the failure in the same log so a SIEM can alert on
    # it. If the log or source is the thing that is broken, this silently
    # cannot, and the non-zero exit is the remaining signal.
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($Source)) {
            if ($null -eq $log) { $log = New-Object System.Diagnostics.EventLog($LogName); $log.Source = $Source }
            Write-AutorunsEvent -Log $log -EventId 101 -Type Error -Message "AutorunsToWinEventLog run FAILED.`r`nError : $err`r`nHost  : $env:COMPUTERNAME"
        }
    } catch { Write-Verbose "could not write failure event: $($_.Exception.Message)" }
    Write-Error $err
    exit 1
}
finally {
    if ($ownCsv -and $null -ne $csvPath -and (Test-Path $csvPath)) { Remove-Item $csvPath -Force -ErrorAction SilentlyContinue }
    if ($null -ne $log) { $log.Dispose() }
}
exit 0
