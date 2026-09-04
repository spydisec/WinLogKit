<#
.SYNOPSIS
    Reports which MITRE ATT&CK techniques a baseline selection makes
    observable - and why the remaining ones are not - using the kit's native
    mapping derived from current ATT&CK data.

.DESCRIPTION
    Default mapping (native): MITRE ATT&CK Enterprise v19.2's own
    detection-strategy/analytics model, flattened to Windows analytic log
    sources and event codes (data\attack\windows_analytics.csv), joined
    through the kit-curated event map (data\attack\event_map.csv) to the
    settings table. Provenance and attribution in data\attack\README.md;
    nothing is fetched at runtime.

    Every technique verdict comes with a reason:

      Observable       an enabling item is selected in this baseline
      NotSelected      the kit has the item, but this selection excludes it
      NotInKit         needs a subcategory the kit deliberately excludes
                       (SACL-dependent Registry/File System, DS Replication...)
      RequiresSysmon   only Sysmon telemetry maps to it (out of kit scope)
      NotNative        needs ETW tracing, EDR, network sensors or cloud logs
      Unmapped         ATT&CK names a source the curated map does not cover
                       yet - reported so curation gaps stay visible

    Caveat: this maps events, not detection quality - "observable" means the
    raw events exist; detection still needs rules.

    -UseOssem switches to the legacy OSSEM-DM snapshot join (data\ossem\,
    OTRF, MIT) as a cross-check; see data\attack\README.md for the credit
    and the relationship between the two mappings.

    Requires: Windows PowerShell 5.1+. No admin, no network; changes nothing.

.PARAMETER BaselineFile
    Selection CSV (New-LoggingBaseline.ps1 or a preset). Without it, tier
    switches decide (Core by default).

.PARAMETER UseOssem
    Use the vendored OSSEM-DM snapshot instead of the native mapping.

.PARAMETER OutDir
    Where the CSVs go. Default: .\Results next to this script.

.EXAMPLE
    .\Export-AttackCoverage.ps1 -IncludeHighVolume

.EXAMPLE
    .\Export-AttackCoverage.ps1 -BaselineFile .\presets\role_Workstation.csv
#>
[CmdletBinding()]
param(
    [string]$BaselineFile,
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    [switch]$UseOssem,
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $PSScriptRoot 'Results' }

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')
. (Join-Path $PSScriptRoot 'WinLogKit.Common.ps1')

# ---------------------------------------------- resolve the selection sets ---

$sel = Resolve-BaselineSelection -BaselineFile $BaselineFile -IncludeHighVolume $IncludeHighVolume -IncludeOptional $IncludeOptional

$subcatSelected = @{}; $subcatKnownByGuid = @{}; $subcatNameByGuid = @{}
foreach ($sub in $script:BaselineAuditSubcategories) {
    $g = $sub.Guid.ToUpper()
    $subcatKnownByGuid[$g] = $true
    $subcatNameByGuid[$g] = $sub.Name
    if (Test-ItemSelected $sel 'AuditPolicy' $sub.Guid $sub.Tier) { $subcatSelected[$g] = $true }
}
$channelSelected = @{}; $channelKnown = @{}
foreach ($ch in $script:BaselineChannels) {
    $channelKnown[$ch.Name] = $true
    if (Test-ItemSelected $sel 'Channel' $ch.Name $ch.Tier) { $channelSelected[$ch.Name] = $true }
}
$regSelected = @{}
foreach ($rs in $script:BaselineRegistrySettings) {
    if (Test-ItemSelected $sel 'Registry' $rs.Id $rs.Tier) { $regSelected[$rs.Id] = $true }
}

function Test-Prereq {
    param([string]$Prereq)
    if ($Prereq -eq '') { return $true }
    if ($Prereq -eq 'ScriptBlock') {
        return ($regSelected.ContainsKey('ScriptBlock64') -or $regSelected.ContainsKey('ScriptBlock32'))
    }
    if ($Prereq -eq 'ModulePair') {
        return (($regSelected.ContainsKey('ModuleLogging64') -and $regSelected.ContainsKey('ModuleNames64')) -or
                ($regSelected.ContainsKey('ModuleLogging32') -and $regSelected.ContainsKey('ModuleNames32')))
    }
    return $false
}

$sourceDesc = $sel.Description

$detail = New-Object System.Collections.Generic.List[object]

if ($UseOssem) {
    # ------------------- legacy cross-check: OSSEM-DM snapshot join ----------
    $snapshot = Join-Path (Join-Path (Join-Path $PSScriptRoot 'data') 'ossem') 'techniques_to_events_windows.csv'
    if (-not (Test-Path $snapshot)) { Write-Error "OSSEM snapshot not found at $snapshot"; exit 1 }
    $subcatAlias = @{ 'PNP Activity' = 'Plug and Play'; 'Policy Change' = 'Audit Policy Change' }
    $subcatSelectedByName = @{}; $subcatKnownByName = @{}
    foreach ($sub in $script:BaselineAuditSubcategories) {
        $subcatKnownByName[$sub.Name] = $true
        if (Test-ItemSelected $sel 'AuditPolicy' $sub.Guid $sub.Tier) { $subcatSelectedByName[$sub.Name] = $true }
    }
    foreach ($r in (Import-Csv $snapshot)) {
        $status = ''; $via = ''
        $sub = $r.audit_sub_category
        if ($sub -ne '' -and $subcatAlias.ContainsKey($sub)) { $sub = $subcatAlias[$sub] }
        if ($r.channel -eq 'Microsoft-Windows-Sysmon/Operational') {
            $status = 'RequiresSysmon'
        } elseif ($sub -eq '' -and $r.channel -eq 'Microsoft-Windows-PowerShell/Operational' -and "$($r.event_id)".Trim() -match '^(4103|4104|4105|4106)$') {
            $isModule = ("$($r.event_id)".Trim() -eq '4103')
            $prereq = 'ScriptBlock'; if ($isModule) { $prereq = 'ModulePair' }
            if (-not $channelSelected.ContainsKey($r.channel)) { $status = 'NotSelected'; $via = "Channel: $($r.channel)" }
            elseif (Test-Prereq $prereq) { $status = 'Observable'; $via = "Channel: $($r.channel) + $prereq policy" }
            else { $status = 'NotSelected'; $via = "Registry: $prereq policy (HighVolume tier)" }
        } elseif ($sub -ne '') {
            if ($subcatSelectedByName.ContainsKey($sub))  { $status = 'Observable'; $via = "AuditPolicy: $sub" }
            elseif ($subcatKnownByName.ContainsKey($sub)) { $status = 'NotSelected'; $via = "AuditPolicy: $sub" }
            else                                          { $status = 'NotInKit'; $via = "Subcategory: $($r.audit_sub_category)" }
        } elseif ($r.channel -ne '') {
            if ($channelSelected.ContainsKey($r.channel))  { $status = 'Observable';  $via = "Channel: $($r.channel)" }
            elseif ($channelKnown.ContainsKey($r.channel)) { $status = 'NotSelected'; $via = "Channel: $($r.channel)" }
            else                                           { $status = 'NotInKit';    $via = "Channel: $($r.channel)" }
        } else { $status = 'NotInKit'; $via = 'No channel/subcategory in OSSEM row' }
        $detail.Add([pscustomobject]@{
            TechniqueId = $r.technique_id; Technique = $r.technique; Tactics = $r.tactics
            LogSource = $r.channel; EventCodes = $r.event_id; Status = $status; ProvidedBy = $via
        })
    }
    $mappingDesc = 'OSSEM-DM snapshot (cross-check mode)'
} else {
    # ------------------------ native mapping: ATT&CK v19.2 + kit event map ---
    # Nested Join-Path keeps these resolvable on non-Windows PowerShell too.
    $attackDir    = Join-Path (Join-Path $PSScriptRoot 'data') 'attack'
    $analyticsCsv = Join-Path $attackDir 'windows_analytics.csv'
    $mapCsv       = Join-Path $attackDir 'event_map.csv'
    foreach ($p in @($analyticsCsv, $mapCsv)) {
        if (-not (Test-Path $p)) { Write-Error "Mapping data not found: $p (see data\attack\README.md)"; exit 1 }
    }

    # Lookup: "source|event" exact, then "source|" fallback.
    $eventMap = @{}
    foreach ($m in (Import-Csv $mapCsv)) {
        $eventMap[("$($m.match_source)|$($m.match_event)")] = $m
    }
    # Status ranking: pick the strongest outcome across an analytic's codes.
    $rank = @{ 'Observable' = 6; 'NotSelected' = 5; 'NotInKit' = 4; 'Unmapped' = 3; 'NotNative' = 2; 'RequiresSysmon' = 1 }

    function Resolve-One {
        param([string]$Source, [string]$Code)
        $m = $null
        if ($eventMap.ContainsKey("$Source|$Code")) { $m = $eventMap["$Source|$Code"] }
        elseif ($eventMap.ContainsKey("$Source|")) { $m = $eventMap["$Source|"] }
        if ($null -eq $m) {
            if ($Source -match '(?i)sysmon') {
                return @{ Status = 'RequiresSysmon'; Via = "Source: $Source" }
            }
            if ($Source -match '^(etw:|ETW:|EDR:|NSM:|m365:|azure:|dns:|Windows:perfmon)') {
                return @{ Status = 'NotNative'; Via = "Source: $Source" }
            }
            return @{ Status = 'Unmapped'; Via = "Source: $Source" }
        }
        if ($m.status -ne '') { return @{ Status = $m.status; Via = "$($m.note)" } }
        if ($m.item_type -eq 'AuditPolicy') {
            $g = $m.item_id.ToUpper()
            if ($subcatSelected.ContainsKey($g))   { return @{ Status = 'Observable';  Via = "AuditPolicy: $($subcatNameByGuid[$g])" } }
            if ($subcatKnownByGuid.ContainsKey($g)) { return @{ Status = 'NotSelected'; Via = "AuditPolicy: $($subcatNameByGuid[$g])" } }
            return @{ Status = 'Unmapped'; Via = "Unknown GUID in event map: $g" }
        }
        if ($m.item_type -eq 'Channel') {
            if (-not $channelKnown.ContainsKey($m.item_id)) { return @{ Status = 'Unmapped'; Via = "Unknown channel in event map: $($m.item_id)" } }
            if (-not $channelSelected.ContainsKey($m.item_id)) { return @{ Status = 'NotSelected'; Via = "Channel: $($m.item_id)" } }
            if (Test-Prereq $m.prereq) { return @{ Status = 'Observable'; Via = "Channel: $($m.item_id)$(if ($m.prereq) { " + $($m.prereq) policy" })" } }
            return @{ Status = 'NotSelected'; Via = "Registry: $($m.prereq) policy (HighVolume tier)" }
        }
        return @{ Status = 'Unmapped'; Via = "Unhandled map row for $Source" }
    }

    foreach ($r in (Import-Csv $analyticsCsv)) {
        $codes = @("$($r.event_codes)".Split(';') | Where-Object { $_ -ne '' })
        if ($codes.Count -eq 0) { $codes = @('') }
        $best = $null
        foreach ($c in $codes) {
            $res = Resolve-One -Source $r.log_source -Code $c
            if ($null -eq $best -or $rank[$res.Status] -gt $rank[$best.Status]) { $best = $res }
        }
        $detail.Add([pscustomobject]@{
            TechniqueId = $r.technique_id; Technique = $r.technique; Tactics = $r.tactics
            LogSource = $r.log_source; EventCodes = $r.event_codes; Status = $best.Status; ProvidedBy = $best.Via
        })
    }
    $mappingDesc = 'MITRE ATT&CK v19.2 (snapshot 2026-08-31) + kit event map'
}

# ------------------------------------------------------- technique rollup ---

$byTech = $detail | Group-Object TechniqueId
$observableCount = 0
$notObservable = New-Object System.Collections.Generic.List[object]
foreach ($g in $byTech) {
    if (@($g.Group | Where-Object { $_.Status -eq 'Observable' }).Count -gt 0) {
        $observableCount++
    } else {
        $reasons = $g.Group | Group-Object Status | Sort-Object Count -Descending
        $notObservable.Add([pscustomobject]@{
            TechniqueId = $g.Name
            Technique   = $g.Group[0].Technique
            Reason      = $reasons[0].Name
        })
    }
}

Write-Host ''
Write-Host "ATT&CK coverage for: $sourceDesc" -ForegroundColor White
Write-Host "Mapping: $mappingDesc ($($byTech.Count) Windows techniques)"
Write-Host ("  Observable techniques : {0} of {1}" -f $observableCount, $byTech.Count) -ForegroundColor Green
foreach ($rg in ($notObservable | Group-Object Reason | Sort-Object Count -Descending)) {
    Write-Host ("  Not observable ({0,-14}): {1}" -f $rg.Name, $rg.Count) -ForegroundColor Yellow
}
Write-Host ''
Write-Host 'Observable = the mapped event sources are enabled, so the events can be produced; detection still needs rules.'
Write-Host '  NotSelected -> selecting more kit items (often HighVolume) adds these.   NotInKit -> excluded subcategories.'
Write-Host '  RequiresSysmon / NotNative -> beyond native host logging.   Unmapped -> curation worklist (see data\attack\README.md).'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailCsv = Join-Path $OutDir "AttackCoverage_Detail_$stamp.csv"
$gapsCsv   = Join-Path $OutDir "AttackCoverage_Gaps_$stamp.csv"
$detail | Export-Csv -Path $detailCsv -NoTypeInformation -Encoding UTF8
$notObservable | Sort-Object Reason, TechniqueId | Export-Csv -Path $gapsCsv -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "Detail CSV: $detailCsv"
Write-Host "Gaps CSV  : $gapsCsv"
exit 0
