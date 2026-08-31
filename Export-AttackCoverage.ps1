<#
.SYNOPSIS
    Reports which MITRE ATT&CK techniques a baseline selection makes
    observable, using the vendored OSSEM Detection Model mappings - and,
    just as importantly, WHY the remaining techniques are not observable.

.DESCRIPTION
    Joins the kit's settings table against the OSSEM-DM snapshot in
    .\data\ossem\ (see its README for provenance; the kit never fetches
    anything at runtime). Every Windows technique-to-event mapping row is
    classified as:

      Observable       the enabling item is selected in this baseline
      NotSelected      the kit has the item, but this selection excludes it
                       (e.g. Process Creation without -IncludeHighVolume)
      NotInKit         the subcategory is deliberately outside the kit's
                       baseline (e.g. Registry / Kernel Object / File System,
                       which are SACL-dependent, or Process Termination)
      RequiresSysmon   only observable via Sysmon, which the kit excludes by
                       design (native Windows logging only)

    A technique counts as observable if at least one of its mapping rows is
    Observable. Techniques with no observable row are listed with the
    dominant reason, so "what would enabling X buy me?" has a data-driven
    answer - the same evidence-based approach as OSSEM's
    attack_techniques_to_events page, computed locally for YOUR selection.

    Caveat: OSSEM maps events, not detection quality. An "observable"
    technique means the raw events exist; detection still needs rules.
    PowerShell channel rows additionally assume script block logging is on
    (a HighVolume tier item).

    Requires: Windows PowerShell 5.1+. No admin, no network; changes nothing.

.PARAMETER BaselineFile
    Selection CSV (New-LoggingBaseline.ps1 or a preset). Without it, tier
    switches decide (Core by default).

.PARAMETER OutDir
    Where the detail CSV goes. Default: .\Results next to this script.

.EXAMPLE
    .\Export-AttackCoverage.ps1 -IncludeHighVolume
    Coverage of Core + HighVolume tiers.

.EXAMPLE
    .\Export-AttackCoverage.ps1 -BaselineFile .\presets\Microsoft_Client.csv
    What the Microsoft client baseline actually makes observable.
#>
[CmdletBinding()]
param(
    [string]$BaselineFile,
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $PSScriptRoot 'Results' }

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')

$snapshot = Join-Path $PSScriptRoot 'data\ossem\techniques_to_events_windows.csv'
if (-not (Test-Path $snapshot)) {
    Write-Error "OSSEM snapshot not found at $snapshot - see data\ossem\README.md."
    exit 1
}

# ---------------------------------------------- resolve the selection sets ---

$selection = $null
if (-not [string]::IsNullOrEmpty($BaselineFile)) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile"
        exit 1
    }
    $selection = @{}
    foreach ($row in (Import-Csv $BaselineFile)) {
        $selection[("$($row.ItemType)|$($row.Id)").ToUpper()] = ("$($row.Selected)".Trim() -match '^(Y|YES|TRUE|1)$')
    }
}

function Test-ItemOn {
    param([string]$ItemType, [string]$Id, [string]$Tier)
    if ($null -ne $selection) {
        $key = ("$ItemType|$Id").ToUpper()
        return ($selection.ContainsKey($key) -and $selection[$key])
    }
    if ($Tier -eq 'Core') { return $true }
    if ($Tier -eq 'HighVolume') { return [bool]$IncludeHighVolume }
    if ($Tier -eq 'Optional') { return [bool]$IncludeOptional }
    return $false
}

# Our subcategory names, split into selected vs known-but-deselected.
$subcatSelected = @{}
$subcatKnown    = @{}
foreach ($sub in $script:BaselineAuditSubcategories) {
    $subcatKnown[$sub.Name] = $true
    if (Test-ItemOn 'AuditPolicy' $sub.Guid $sub.Tier) { $subcatSelected[$sub.Name] = $true }
}
$channelSelected = @{}
$channelKnown    = @{}
foreach ($ch in $script:BaselineChannels) {
    $channelKnown[$ch.Name] = $true
    if (Test-ItemOn 'Channel' $ch.Name $ch.Tier) { $channelSelected[$ch.Name] = $true }
}

# OSSEM subcategory names that differ from the kit's.
$subcatAlias = @{
    'PNP Activity'  = 'Plug and Play'
    'Policy Change' = 'Audit Policy Change'
}

$sourceDesc = "Core tier$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
if ($null -ne $selection) { $sourceDesc = "baseline file $(Split-Path $BaselineFile -Leaf)" }

# --------------------------------------------------------------- classify ---

$rows = Import-Csv $snapshot
$detail = New-Object System.Collections.Generic.List[object]

foreach ($r in $rows) {
    $status = ''
    $via = ''
    $sub = $r.audit_sub_category
    if ($sub -ne '' -and $subcatAlias.ContainsKey($sub)) { $sub = $subcatAlias[$sub] }

    if ($r.channel -eq 'Microsoft-Windows-Sysmon/Operational') {
        $status = 'RequiresSysmon'
    } elseif ($sub -ne '') {
        if ($subcatSelected.ContainsKey($sub))  { $status = 'Observable'; $via = "AuditPolicy: $sub" }
        elseif ($subcatKnown.ContainsKey($sub)) { $status = 'NotSelected'; $via = "AuditPolicy: $sub" }
        else                                    { $status = 'NotInKit';   $via = "Subcategory: $($r.audit_sub_category)" }
    } elseif ($r.channel -ne '') {
        if ($channelSelected.ContainsKey($r.channel))  { $status = 'Observable';  $via = "Channel: $($r.channel)" }
        elseif ($channelKnown.ContainsKey($r.channel)) { $status = 'NotSelected'; $via = "Channel: $($r.channel)" }
        else                                           { $status = 'NotInKit';    $via = "Channel: $($r.channel)" }
    } else {
        $status = 'NotInKit'; $via = 'No channel/subcategory in OSSEM row'
    }

    $detail.Add([pscustomobject]@{
        TechniqueId   = $r.technique_id
        Technique     = $r.technique
        Tactics       = $r.tactics
        DataComponent = $r.data_component
        EventId       = $r.event_id
        EventName     = $r.event_name
        Channel       = $r.channel
        Subcategory   = $r.audit_sub_category
        Status        = $status
        ProvidedBy    = $via
    })
}

# ------------------------------------------------------- technique rollup ---

$byTech = $detail | Group-Object TechniqueId
$observable = New-Object System.Collections.Generic.List[object]
$notObservable = New-Object System.Collections.Generic.List[object]
foreach ($g in $byTech) {
    $obs = @($g.Group | Where-Object { $_.Status -eq 'Observable' })
    if ($obs.Count -gt 0) {
        $observable.Add($g.Group[0])
    } else {
        # Dominant reason: what would it take to see this technique?
        $reasons = $g.Group | Group-Object Status | Sort-Object Count -Descending
        $notObservable.Add([pscustomobject]@{
            TechniqueId = $g.Name
            Technique   = $g.Group[0].Technique
            Reason      = $reasons[0].Name
        })
    }
}

Write-Host ''
Write-Host "ATT&CK coverage for: $sourceDesc (OSSEM-DM snapshot, $($byTech.Count) Windows techniques mapped)" -ForegroundColor White
Write-Host ("  Observable techniques : {0} of {1}" -f $observable.Count, $byTech.Count) -ForegroundColor Green
$reasonGroups = $notObservable | Group-Object Reason | Sort-Object Count -Descending
foreach ($rg in $reasonGroups) {
    Write-Host ("  Not observable ({0,-14}): {1}" -f $rg.Name, $rg.Count) -ForegroundColor Yellow
}
Write-Host ''
Write-Host 'Interpretation: Observable = the enabling events exist on hosts with this baseline.'
Write-Host '  NotSelected    -> selecting more kit items (often the HighVolume tier) would add these.'
Write-Host '  NotInKit       -> needs SACL-dependent or deliberately excluded subcategories.'
Write-Host '  RequiresSysmon -> only Sysmon telemetry maps to these; native logging cannot see them (kit scope).'

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailCsv = Join-Path $OutDir "AttackCoverage_Detail_$stamp.csv"
$gapsCsv   = Join-Path $OutDir "AttackCoverage_Gaps_$stamp.csv"
$detail | Export-Csv -Path $detailCsv -NoTypeInformation -Encoding UTF8
$notObservable | Sort-Object Reason, TechniqueId | Export-Csv -Path $gapsCsv -NoTypeInformation -Encoding UTF8
Write-Host ''
Write-Host "Detail CSV (every mapping row): $detailCsv"
Write-Host "Gaps CSV (techniques not observable, with reason): $gapsCsv"
exit 0
