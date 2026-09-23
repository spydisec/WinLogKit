<#
.SYNOPSIS
    Regenerates docs\reference.md - the one-table reference of every kit
    item: key events, size, volume weight, which reference baselines ask for
    it, and which role presets include it. Run after changing the settings
    table or presets; CI fails if the committed page drifts.

.DESCRIPTION
    Everything is derived, never hand-written:
      - items and sizes: WinLogKit.Settings.ps1
      - key events: the curated ATT&CK event map (authoritative for audit
        subcategories) plus event IDs mentioned in each item's Purpose text
      - reference membership: the ASD / Microsoft_Client / Microsoft_Server
        definitions in tools\reference-baselines.psd1; Y = in Yamato's set
        (the kit's Core and HighVolume tiers, per the documented deviations)
      - Wks / Mbr / DC: the Workstation / MemberServer / DomainController
        preset CSVs
      - volume weight: High = HighVolume tier, Watch = Core with a Risk
        note, Low = everything else

    Requires: Windows PowerShell 5.1+. No admin; writes only the doc page.
#>
[CmdletBinding()]
param(
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$kitRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrEmpty($OutFile)) { $OutFile = Join-Path (Join-Path $kitRoot 'docs') 'reference.md' }

. (Join-Path $kitRoot 'WinLogKit.Settings.ps1')
. (Join-Path $kitRoot 'WinLogKit.Common.ps1')
$references = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'reference-baselines.psd1')

# ---- preset membership lookups ----------------------------------------------

function Import-SelectedSet {
    param([string]$Name)
    $set = @{}
    foreach ($row in (Import-Csv (Join-Path (Join-Path $kitRoot 'presets') "$Name.csv"))) {
        if ("$($row.Selected)".Trim() -eq 'Y') { $set[("$($row.ItemType)|$($row.Id)").ToUpper()] = $true }
    }
    return $set
}
$selWks = Import-SelectedSet 'Workstation'
$selMbr = Import-SelectedSet 'MemberServer'
$selDc  = Import-SelectedSet 'DomainController'

# Audit-subcategory event IDs from the curated event map (authoritative).
$eventsByGuid = @{}
foreach ($m in (Import-Csv (Join-Path (Join-Path (Join-Path $kitRoot 'data') 'attack') 'event_map.csv'))) {
    if ($m.item_type -eq 'AuditPolicy' -and $m.item_id -ne '' -and $m.match_event -ne '') {
        $g = $m.item_id.ToUpper()
        if (-not $eventsByGuid.ContainsKey($g)) { $eventsByGuid[$g] = New-Object System.Collections.Generic.List[string] }
        $eventsByGuid[$g].Add($m.match_event)
    }
}

# Best-effort event IDs mentioned in Purpose text (filters out years/counts
# and the AD CS AuditFilter bitmask value 127; hyphenated ranges like
# 5478-5485 are kept intact).
$junk = @('2000', '2008', '2012', '2016', '2019', '2022', '2025', '127')
function Get-PurposeEventText {
    param([string]$Purpose)
    $ids = [regex]::Matches($Purpose, '\b\d{3,5}(-\d{2,5})?\b') | ForEach-Object { $_.Value } |
        Where-Object { $junk -notcontains $_ } | Select-Object -Unique
    return @($ids)
}

# Kit-added items that Yamato's own scripts do not contain: the Server 2025
# SMB auditing (all SmbAudit rows plus its two channels), the NTLM audit
# registry values and the PowerShell 7 policy fallbacks (#44). They must not
# carry the Y letter. Situational items (the old Optional tier: IPsec Driver,
# the DPAPI debug channel) are opt-in extras outside Yamato's set too,
# whatever their tier.
$yExcludedIds = @('NtlmOutboundAudit', 'NtlmInboundAudit', 'NtlmDomainAudit',
    'PS7ScriptBlock64', 'PS7ScriptBlock32', 'PS7ModuleLogging64', 'PS7ModuleLogging32')
$yExcludedChannels = @('Microsoft-Windows-SMBServer/Audit', 'Microsoft-Windows-SmbClient/Audit')
function Test-Situational {
    param([hashtable]$Item)
    return ($Item.ContainsKey('Situational') -and $Item.Situational)
}

function Format-RefText {
    param([string]$ItemType, [string]$Id, [string]$Tier, [bool]$Situational = $false)
    $refs = @()
    if (Test-ReferenceBaselineItem $references.ASD $ItemType $Id)              { $refs += 'A' }
    if (Test-ReferenceBaselineItem $references.Microsoft_Client $ItemType $Id) { $refs += 'C' }
    if (Test-ReferenceBaselineItem $references.Microsoft_Server $ItemType $Id) { $refs += 'S' }
    $isYamato = ($Tier -eq 'Core' -or $Tier -eq 'HighVolume') -and -not $Situational -and
        $ItemType -ne 'SmbAudit' -and
        ($yExcludedIds -notcontains $Id) -and
        -not ($ItemType -eq 'Channel' -and $yExcludedChannels -contains $Id)
    if ($isYamato) { $refs += 'Y' }
    if ($refs.Count -eq 0) { return '-' }
    return ($refs -join ' ')
}

function Format-Tick {
    param([hashtable]$Set, [string]$ItemType, [string]$Id)
    if ($Set.ContainsKey(("$ItemType|$Id").ToUpper())) { return ':material-check:' }
    return '-'
}

# The three role columns for one item.
function Format-RoleColumn {
    param([string]$ItemType, [string]$Id)
    return ('{0} | {1} | {2}' -f (Format-Tick $selWks $ItemType $Id), (Format-Tick $selMbr $ItemType $Id), (Format-Tick $selDc $ItemType $Id))
}

function Format-Volume {
    param([hashtable]$Item)
    # Situational items are opt-in for relevance, not volume: label them from
    # their Risk note like any Core item.
    if ($Item.Tier -eq 'HighVolume' -and -not (Test-Situational $Item)) { return 'High' }
    if ($Item.ContainsKey('Risk') -and "$($Item.Risk)" -ne '') { return 'Watch' }
    return 'Low'
}

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "$([math]::Round($Bytes/1GB)) GB" }
    return "$([math]::Round($Bytes/1MB)) MB"
}

# ---- build rows -------------------------------------------------------------

$rows = New-Object System.Collections.Generic.List[string]

foreach ($ch in $script:BaselineChannels) {
    $ev = (Get-PurposeEventText $ch.Purpose) -join ', '
    if ($ev -eq '') { $ev = '-' }
    $rows.Add("| $($ch.Name) | Channel | $ev | $($ch.DefaultSize) -> $(Format-Size $ch.TargetBytes) | $(Format-Volume $ch) | $(Format-RefText 'Channel' $ch.Name $ch.Tier (Test-Situational $ch)) | $(Format-RoleColumn 'Channel' $ch.Name) |")
}
foreach ($sub in $script:BaselineAuditSubcategories) {
    $g = $sub.Guid.ToUpper()
    # Merge both sources: event-map IDs (authoritative) plus any further IDs
    # documented in the Purpose, deduplicated.
    $ids = New-Object System.Collections.Generic.List[string]
    if ($eventsByGuid.ContainsKey($g)) {
        foreach ($i in (@($eventsByGuid[$g]) | Sort-Object -Unique)) { $ids.Add($i) }
    }
    foreach ($i in (Get-PurposeEventText $sub.Purpose)) {
        if (-not $ids.Contains($i)) { $ids.Add($i) }
    }
    $ev = $ids -join ', '
    if ($ev -eq '') { $ev = '-' }
    $name = $sub.Name
    if ($sub.Scope -eq 'DomainController') { $name += ' (DC)' }
    $rows.Add("| $name | Audit subcategory | $ev | - | $(Format-Volume $sub) | $(Format-RefText 'AuditPolicy' $sub.Guid $sub.Tier (Test-Situational $sub)) | $(Format-RoleColumn 'AuditPolicy' $sub.Guid) |")
}
foreach ($rs in $script:BaselineRegistrySettings) {
    $ev = (Get-PurposeEventText $rs.Purpose) -join ', '
    if ($ev -eq '') { $ev = '-' }
    $name = "$($rs.Path -replace '^HKLM:\\SOFTWARE\\', '' -replace '^HKLM:\\SYSTEM\\', '')\$($rs.Name)"
    if ($rs.Scope -eq 'DomainController') { $name += ' (DC)' }
    $rows.Add("| ``$name`` | Registry | $ev | - | $(Format-Volume $rs) | $(Format-RefText 'Registry' $rs.Id $rs.Tier) | $(Format-RoleColumn 'Registry' $rs.Id) |")
}
$af = $script:BaselineAdcsAuditFilter
$rows.Add("| AD CS AuditFilter (needs CertSvc restart) | Registry | $((Get-PurposeEventText $af.Purpose) -join ', ') | - | $(Format-Volume $af) | $(Format-RefText 'Registry' $af.Id $af.Tier) | $(Format-RoleColumn 'Registry' $af.Id) |")
foreach ($sa in $script:BaselineSmbAuditSettings) {
    $rows.Add("| $($sa.Side): $($sa.Id) | SMB audit (2025+) | $((Get-PurposeEventText $sa.Purpose) -join ', ') | - | Low | $(Format-RefText 'SmbAudit' $sa.Id $sa.Tier) | $(Format-RoleColumn 'SmbAudit' $sa.Id) |")
}

# ---- write the page ---------------------------------------------------------

$header = @'
# Reference

<!-- GENERATED by tools\Export-ReferenceTable.ps1 - do not edit by hand.
     CI fails if this page drifts from the settings table and presets. -->

Every setting in the kit, one row each: the events it produces, the log
size the kit applies, how heavy it is, who recommends it, and which
[role presets](baselines.md#role-presets) include it.

Reading the columns:

- **Key events** - the main event IDs the setting produces. Audit rows come
  from the kit's curated [ATT&CK event map](mapping.md); others are the IDs
  named in the setting's own documentation. Indicative, not exhaustive.
- **Size** - default -> kit target, for event log channels.
- **Volume** - how heavy the logs get: **High** = a high-volume generator
  (the HighVolume tier), **Watch** = normal volume with a documented
  pilot-week caution, **Low** = quiet. Two HighVolume items are opt-in only
  because they matter in some environments, not because they are loud (IPsec
  Driver, the DPAPI debug channel); they show Watch or Low.
- **Refs** - who asks for it: **A** = ASD, **C** = Microsoft Client,
  **S** = Microsoft Server, **Y** = Yamato (per the reference definitions in
  `tools\reference-baselines.psd1`; kit-added extras such as the Server 2025
  SMB auditing and the NTLM audit values, and those two opt-in items, show
  no Y and are sourced in the
  [settings table](https://github.com/spydisec/WinLogKit/blob/main/WinLogKit.Settings.ps1)).
- **Wks / Mbr / DC** - membership in the `Workstation`, `MemberServer` and
  `DomainController` presets (rows marked **(DC)** only apply on domain
  controllers).

| Setting | Type | Key events | Size | Volume | Refs | Wks | Mbr | DC |
|---|---|---|---|---|---|---|---|---|
'@

# Here-strings drop their final newline: add it, or the first row would
# concatenate onto the table separator.
$content = $header + "`n" + ($rows -join "`n") + "`n"
[System.IO.File]::WriteAllText($OutFile, $content, (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Reference page written: $OutFile ($($rows.Count) rows)"
exit 0
