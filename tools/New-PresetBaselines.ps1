<#
.SYNOPSIS
    Regenerates the baseline presets in .\presets\ from the settings table.
    Run after changing WinLogKit.Settings.ps1; CI fails if the committed
    presets drift from what this script produces.

.DESCRIPTION
    Each preset is a normal selection CSV (same schema as New-LoggingBaseline
    output) expressing a baseline as a SELECTION of the kit's items. Four
    ship (ADR-002):

    Role presets - the kit's recommended starting point per host role,
    derived from the settings table's own Risk metadata and Microsoft's
    per-role audit recommendations. Starting points pending pilot volume
    data, not final answers (see docs "Role presets" for the rationale per
    decision):

      Workstation.csv        Core + process creation/cmdline + script block
                             logging (Windows PowerShell and PowerShell 7)
                             + WFP connections; DC-only items deselected
      MemberServer.csv       as Workstation but WITHOUT WFP connections
                             (documented High volume on connection-heavy
                             servers)
      DomainController.csv   as MemberServer plus the DC-scope subcategories

    Module logging and Sensitive Privilege Use stay opt-in in every role
    preset (extreme volume / backup-agent flood, per their Risk notes).

    Reference preset - faithful to Yamato Security's EventLog-Baseline-Guide
    bat/ASD.bat (definition in tools\reference-baselines.psd1, which also
    holds the Microsoft client/server definitions used only for the
    Reference page's Refs column):

      ASD.csv                Australian Signals Directorate

    Faithfulness limits (documented on the Baselines page):
      - The kit applies its own Success/Failure flags and channel sizes, which
        are supersets of the reference in places (ASD sizes Security at 2 GB
        where the kit uses 1 GB - the one case the kit is smaller).
      - Five ASD subcategories are not in the kit's settings table because
        Yamato's own baseline leaves them off (Process Termination, Group
        Membership, File System, Kernel Object, Registry - the last three are
        SACL-dependent). They cannot be expressed by a preset.
      - Registry-view fidelity: where a baseline sets PowerShell logging via
        the Wow6432Node path only, the preset selects the kit's both-view
        items.

    Requires: Windows PowerShell 5.1+. No admin. Changes nothing on the host.
    Run it under Windows PowerShell 5.1 so the CSVs keep their UTF-8 BOM.
#>
[CmdletBinding()]
param(
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$kitRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $kitRoot 'presets' }

. (Join-Path $kitRoot 'WinLogKit.Settings.ps1')
. (Join-Path $kitRoot 'WinLogKit.Common.ps1')
$references = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'reference-baselines.psd1')

# Get the full item list from the builder itself - no duplicated flattening
# logic; the Selected column is overwritten per preset below.
$allItemsCsv = Join-Path ([IO.Path]::GetTempPath()) "winlogkit-preset-src-$PID.csv"
& (Join-Path $kitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -OutFile $allItemsCsv -Force | Out-Null
$rows = Import-Csv $allItemsCsv
Remove-Item $allItemsCsv -Force

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

function Write-Preset {
    param([string]$Name, [object[]]$OutRows)
    $outFile = Join-Path $OutDir "$Name.csv"
    $OutRows | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    $count = @($OutRows | Where-Object { $_.Selected -eq 'Y' }).Count
    Write-Host ("{0}  {1} of {2} items selected" -f $outFile, $count, @($OutRows).Count)
}

# ---------------------------------------------------------- role presets ---
# Base = the builder's recommended (Core) defaults, then per-role deltas.
# ExtraAudit prefixes: 0CCE922B = Process Creation, 0CCE9226 = Filtering
# Platform Connection.

$rolePresets = @(
    @{ Name = 'Workstation';      IncludeDcScope = $false
       ExtraAudit = @('0CCE922B', '0CCE9226')
       ExtraReg   = @('CmdLineAudit', 'ScriptBlock64', 'ScriptBlock32', 'PS7ScriptBlock64', 'PS7ScriptBlock32') }
    @{ Name = 'MemberServer';     IncludeDcScope = $false
       ExtraAudit = @('0CCE922B')
       ExtraReg   = @('CmdLineAudit', 'ScriptBlock64', 'ScriptBlock32', 'PS7ScriptBlock64', 'PS7ScriptBlock32') }
    @{ Name = 'DomainController'; IncludeDcScope = $true
       ExtraAudit = @('0CCE922B')
       ExtraReg   = @('CmdLineAudit', 'ScriptBlock64', 'ScriptBlock32', 'PS7ScriptBlock64', 'PS7ScriptBlock32') }
)

# Guard against silent selector drift: every selector must match at least
# one settings-table item, or generation fails (CI runs this on every push
# via the preset drift check).
foreach ($rp in $rolePresets) {
    foreach ($prefix in $rp.ExtraAudit) {
        if (-not @($rows | Where-Object { $_.ItemType -eq 'AuditPolicy' -and $_.Id.ToUpper().StartsWith($prefix) }).Count) {
            Write-Error "Role preset $($rp.Name): audit selector '$prefix' matches no settings-table item."
            exit 1
        }
    }
    foreach ($regId in $rp.ExtraReg) {
        if (-not @($rows | Where-Object { $_.ItemType -eq 'Registry' -and $_.Id -eq $regId }).Count) {
            Write-Error "Role preset $($rp.Name): registry selector '$regId' matches no settings-table item."
            exit 1
        }
    }
}

foreach ($rp in $rolePresets) {
    $outRows = foreach ($row in $rows) {
        # Start from the kit recommendation (Core tier selected).
        $selected = $row.Recommended
        # Role deltas.
        if ($row.ItemType -eq 'AuditPolicy') {
            foreach ($prefix in $rp.ExtraAudit) {
                if ($row.Id.ToUpper().StartsWith($prefix)) { $selected = 'Y'; break }
            }
        }
        if ($row.ItemType -eq 'Registry' -and $rp.ExtraReg -contains $row.Id) { $selected = 'Y' }
        # Non-DC roles express intent explicitly rather than relying on
        # runtime NOT APPLICABLE gating.
        if ($row.Scope -eq 'DomainController' -and -not $rp.IncludeDcScope) { $selected = 'N' }
        $row.Selected = $selected
        $row
    }
    Write-Preset -Name $rp.Name -OutRows $outRows
}

# ------------------------------------------------------- reference preset ---

$outRows = foreach ($row in $rows) {
    $row.Selected = 'N'
    if (Test-ReferenceBaselineItem -Definition $references.ASD -ItemType $row.ItemType -Id $row.Id) { $row.Selected = 'Y' }
    $row
}
Write-Preset -Name 'ASD' -OutRows $outRows

Write-Host ''
Write-Host 'Presets regenerated. Inspect any of them with:'
Write-Host ("  {0} -Show -BaselineFile {1}" -f (Join-Path $kitRoot 'New-LoggingBaseline.ps1'), (Join-Path $OutDir 'Workstation.csv'))
exit 0
