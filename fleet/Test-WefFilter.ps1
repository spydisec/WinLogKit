<#
.SYNOPSIS
    On a Windows Event Collector, proves that a WEF subscription's filter is
    actually in effect: compares what ForwardedEvents received against what
    New-WefSubscription.ps1 said it should deliver, and (optionally) that
    the deployed subscription is the generated one.

.DESCRIPTION
    A subscription can be generated correctly and still not be what runs:
    someone edits it on the collector, an older version stays registered,
    or a second subscription forwards more. This script answers "is the
    filter working?" from evidence, not configuration:

      1. Reads the sidecar <SubscriptionId>.expected-eventids.csv written by
         New-WefSubscription.ps1 (channel -> allowed event IDs, or '*').
      2. Reads ForwardedEvents for the last -Hours and groups by original
         channel and event ID (forwarded records keep their source channel).
      3. Reports, per channel:
           UNEXPECTED  event IDs that arrived but are not in the allowed set
                       (the filter is not applied, or another subscription
                       forwards them) - a failure
           expected    allowed IDs that were seen
           unseen      allowed IDs not seen in the window (informational:
                       the source may simply not have produced them)
      4. With -SubscriptionId, also pulls the deployed subscription with
         wecutil and checks its <Query> matches the generated XML next to
         the sidecar, so a hand edit or stale registration shows up.
      5. Prints the equivalent Sentinel KQL so the same check can run at
         the workspace end.

    Exit code 1 on any UNEXPECTED ID or a query mismatch; 0 otherwise.

    Requires: run on the collector; reading ForwardedEvents needs the Event
    Log Readers group or admin; wecutil needs admin.

.PARAMETER ExpectedFile
    The sidecar CSV from New-WefSubscription.ps1.

.PARAMETER Hours
    Lookback window over ForwardedEvents. Default 24.

.PARAMETER MaxEvents
    Cap on records read (a busy collector holds millions). Default 200000;
    the report says when the cap was hit.

.PARAMETER SubscriptionId
    Also verify the deployed subscription's query against the generated XML
    (<SubscriptionId>.xml next to the sidecar).

.EXAMPLE
    .\fleet\Test-WefFilter.ps1 -ExpectedFile .\WEF\WinLogKit-Baseline.expected-eventids.csv -SubscriptionId WinLogKit-Baseline
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string]$ExpectedFile,
    [int]$Hours = 24,
    [int]$MaxEvents = 200000,
    [string]$SubscriptionId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$failed = $false

if (-not (Test-Path $ExpectedFile)) { Write-Error "Expected-delivery file not found: $ExpectedFile"; exit 1 }

# ---- 1. expected delivery ---------------------------------------------------
$allowed = @{}      # channel -> hashtable of int -> $true, or $null for whole channel
foreach ($row in (Import-Csv $ExpectedFile)) {
    if (-not $allowed.ContainsKey($row.Channel)) { $allowed[$row.Channel] = @{} }
    if ($row.EventID -eq '*') { $allowed[$row.Channel] = $null; continue }
    if ($null -ne $allowed[$row.Channel]) { $allowed[$row.Channel][[int]$row.EventID] = $true }
}

# ---- 2. what actually arrived ----------------------------------------------
$since = (Get-Date).AddHours(-$Hours)
Write-Host "Reading ForwardedEvents since $since (cap $MaxEvents records)..." -ForegroundColor White
try {
    $records = @(Get-WinEvent -FilterHashtable @{ LogName = 'ForwardedEvents'; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop)
} catch {
    if ("$($_.FullyQualifiedErrorId)" -match 'NoMatchingEventsFound') {
        $records = @()
    } else {
        # Cannot read the log at all (rights, missing log): no evidence, no
        # verdict, and a hard failure so automation never mistakes it for a pass.
        Write-Host "Cannot read ForwardedEvents: $($_.Exception.Message) [$($_.FullyQualifiedErrorId)]" -ForegroundColor Red
        Write-Host 'Run as an administrator or a member of Event Log Readers on the collector.' -ForegroundColor Red
        Write-Host 'WEF filter check: FAIL (ForwardedEvents unreadable)' -ForegroundColor Red
        exit 1
    }
}
if ($records.Count -eq 0) {
    # No evidence is not a pass. Exit 2 so automation can tell "inconclusive"
    # from "filter verified".
    Write-Warning "ForwardedEvents holds no records in the last $Hours h. Nothing to compare - check sources are registered and active (wecutil gr) and try a wider -Hours."
    Write-Host 'WEF filter check: INCONCLUSIVE (no forwarded events to examine)' -ForegroundColor Yellow
    exit 2
}
if ($records.Count -ge $MaxEvents) { Write-Warning "Read cap of $MaxEvents hit; the comparison covers the newest $MaxEvents records only." }

# A forwarded record keeps its source channel (Security, System, ...) in the
# event's System/Channel element, which EventLogRecord exposes as LogName;
# ContainerLog is the log it physically sits in (ForwardedEvents). Should a
# record ever report the container as its LogName, fall back to the XML.
# https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.eventlogrecord.containerlog
$observed = @{}     # channel -> hashtable id -> count
$sampleHost = @{}   # "channel|id" -> a source computer name for the report
foreach ($r in $records) {
    $ch = $r.LogName
    if ($ch -eq 'ForwardedEvents') {
        try { $ch = ([xml]$r.ToXml()).Event.System.Channel } catch { Write-Verbose "channel fallback failed for record $($r.RecordId)" }
    }
    if (-not $observed.ContainsKey($ch)) { $observed[$ch] = @{} }
    if (-not $observed[$ch].ContainsKey($r.Id)) { $observed[$ch][$r.Id] = 0; $sampleHost["$ch|$($r.Id)"] = $r.MachineName }
    $observed[$ch][$r.Id]++
}

# ---- 3. compare -------------------------------------------------------------
Write-Host ''
foreach ($ch in ($allowed.Keys | Sort-Object)) {
    $seen = if ($observed.ContainsKey($ch)) { $observed[$ch] } else { @{} }
    if ($null -eq $allowed[$ch]) {
        Write-Host ("{0,-50} whole channel: {1} event IDs, {2} records" -f $ch, $seen.Count, (($seen.Values | Measure-Object -Sum).Sum))
        continue
    }
    $unexpected = @($seen.Keys | Where-Object { -not $allowed[$ch].ContainsKey($_) } | Sort-Object)
    $expectedSeen = @($seen.Keys | Where-Object { $allowed[$ch].ContainsKey($_) }).Count
    $unseen = @($allowed[$ch].Keys | Where-Object { -not $seen.ContainsKey($_) }).Count
    $verdict = if ($unexpected.Count -eq 0) { 'PASS' } else { 'FAIL' }
    $colour  = if ($unexpected.Count -eq 0) { 'Green' } else { 'Red' }
    Write-Host ("{0,-50} {1}: {2} allowed IDs, {3} seen, {4} unseen, {5} UNEXPECTED" -f $ch, $verdict, $allowed[$ch].Count, $expectedSeen, $unseen, $unexpected.Count) -ForegroundColor $colour
    foreach ($id in $unexpected) {
        Write-Host ("    unexpected {0,6}  x{1,-7} e.g. from {2}" -f $id, $seen[$id], $sampleHost["$ch|$id"]) -ForegroundColor Red
        $failed = $true
    }
}
foreach ($ch in ($observed.Keys | Where-Object { -not $allowed.ContainsKey($_) } | Sort-Object)) {
    Write-Host ("{0,-50} WARN: channel not in the expected file but present ({1} records) - another subscription forwards it" -f $ch, (($observed[$ch].Values | Measure-Object -Sum).Sum)) -ForegroundColor Yellow
}

# ---- 4. deployed subscription matches the generated file -------------------
if (-not [string]::IsNullOrEmpty($SubscriptionId)) {
    Write-Host ''
    $xmlPath = Join-Path (Split-Path (Resolve-Path $ExpectedFile).Path -Parent) "$SubscriptionId.xml"
    if (-not (Test-Path $xmlPath)) {
        Write-Warning "Generated XML not found next to the sidecar ($xmlPath); skipping the deployed-query comparison."
    } else {
        $deployedRaw = & wecutil.exe gs $SubscriptionId /f:xml 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Deployed subscription '$SubscriptionId': wecutil could not read it ($($deployedRaw -join ' '))" -ForegroundColor Red
            $failed = $true
        } else {
            $norm = { param($s) ($s -replace '\s+', ' ').Trim() }
            $deployedQuery  = & $norm (([xml]($deployedRaw -join "`n")).Subscription.Query.InnerText)
            $generatedQuery = & $norm (([xml](Get-Content $xmlPath -Raw)).Subscription.Query.InnerText)
            if ($deployedQuery -eq $generatedQuery) {
                Write-Host "Deployed subscription '$SubscriptionId': query matches the generated file" -ForegroundColor Green
            } else {
                Write-Host "Deployed subscription '$SubscriptionId': query DIFFERS from the generated file (hand-edited, or a stale version is registered)" -ForegroundColor Red
                $failed = $true
            }
        }
    }
}

# ---- 5. the same check at the SIEM end -------------------------------------
$secAllowed = if ($allowed.ContainsKey('Security') -and $null -ne $allowed['Security']) { @($allowed['Security'].Keys | Sort-Object) } else { @() }
if ($secAllowed.Count -gt 0) {
    Write-Host ''
    Write-Host 'Same check in Sentinel (any row returned = an event the filter should have stopped):' -ForegroundColor White
    Write-Host 'WindowsEvent'
    Write-Host "| where TimeGenerated > ago(${Hours}h) and Channel == `"Security`""
    Write-Host "| where EventID !in ($($secAllowed -join ', '))"
    Write-Host '| summarize Events = count() by EventID, Computer'
    Write-Host '| order by Events desc'
}

Write-Host ''
if ($failed) { Write-Host 'WEF filter check: FAIL' -ForegroundColor Red; exit 1 }
Write-Host 'WEF filter check: PASS' -ForegroundColor Green
exit 0
