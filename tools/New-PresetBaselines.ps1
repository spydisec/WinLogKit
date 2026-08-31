<#
.SYNOPSIS
    Regenerates the reference baseline presets in .\presets\ from the settings
    table. Run after changing LoggingBaseline.Settings.ps1; CI fails if the
    committed presets drift from what this script produces.

.DESCRIPTION
    Each preset is a normal selection CSV (same schema as New-LoggingBaseline
    output) expressing a baseline as a SELECTION of the kit's items.

    Reference presets - faithful to the corresponding script in Yamato
    Security's EventLog-Baseline-Guide repo (bat/ASD.bat,
    bat/Microsoft_Client.bat, bat/Microsoft_Server.bat, extracted 2026-08-31):

      ASD.csv                Australian Signals Directorate
      Microsoft_Client.csv   Microsoft client OS baseline recommendation
      Microsoft_Server.csv   Microsoft server OS baseline recommendation

    Role presets - the kit's recommended starting point per host role,
    derived from the settings table's own Risk metadata and Microsoft's
    per-role audit recommendations. Starting points pending pilot volume
    data, not final answers (see docs "Per-role presets" for the rationale
    per decision):

      role_Workstation.csv        Core + process creation/cmdline + script
                                  block logging + WFP connections; DC-only
                                  items deselected
      role_MemberServer.csv       as Workstation but WITHOUT WFP connections
                                  (documented High volume on connection-heavy
                                  servers)
      role_DomainController.csv   as MemberServer plus the DC-scope
                                  subcategories

    Module logging and Sensitive Privilege Use stay opt-in in every role
    preset (extreme volume / backup-agent flood, per their Risk notes).

    Faithfulness limits (documented in the README):
      - The kit applies its own Success/Failure flags and channel sizes, which
        are supersets of these baselines in places (e.g. ASD sizes Security at
        2 GB where the kit uses 1 GB - the one case the kit is smaller).
      - Five ASD subcategories are not in the kit's settings table because
        Yamato's own baseline leaves them off (Process Termination, Group
        Membership, File System, Kernel Object, Registry - the last three are
        SACL-dependent). They cannot be expressed by a preset.
      - Registry-view fidelity: where a baseline sets PowerShell logging via
        the Wow6432Node path only, the preset selects the kit's both-view
        items.

    Requires: Windows PowerShell 5.1+. No admin. Changes nothing on the host.
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

# Preset definitions. AuditPrefixes are the first GUID segment of the enabled
# subcategories in the corresponding EventLog-Baseline-Guide bat file.
$presets = @(
    @{
        Name = 'ASD'
        AuditPrefixes = @('0CCE9236','0CCE923A','0CCE9237','0CCE9235','0CCE922B','0CCE9217','0CCE9216','0CCE9215','0CCE921C','0CCE921B','0CCE9224','0CCE9227','0CCE922F','0CCE9234','0CCE9212')
        RegistryIds   = @('CmdLineAudit','ScriptBlock64','ScriptBlock32','ModuleLogging64','ModuleLogging32','ModuleNames64','ModuleNames32')
        Channels      = @('Security','System','Application')
    }
    @{
        Name = 'Microsoft_Client'
        AuditPrefixes = @('0CCE923F','0CCE9236','0CCE923A','0CCE9237','0CCE9235','0CCE922B','0CCE9216','0CCE9215','0CCE921B','0CCE922F','0CCE9213','0CCE9210','0CCE9211','0CCE9212')
        RegistryIds   = @('CmdLineAudit')
        Channels      = @()
    }
    @{
        Name = 'Microsoft_Server'
        AuditPrefixes = @('0CCE923F','0CCE9236','0CCE923A','0CCE9237','0CCE9235','0CCE922B','0CCE923B','0CCE923C','0CCE9216','0CCE9215','0CCE921B','0CCE922F','0CCE9213','0CCE9210','0CCE9211','0CCE9212')
        RegistryIds   = @('CmdLineAudit')
        Channels      = @()
    }
)

# Get the full item list from the builder itself - no duplicated flattening
# logic; the Selected column is overwritten per preset below.
$allItemsCsv = Join-Path ([IO.Path]::GetTempPath()) "winlogkit-preset-src-$PID.csv"
& (Join-Path $kitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -OutFile $allItemsCsv -Force | Out-Null
$rows = Import-Csv $allItemsCsv
Remove-Item $allItemsCsv -Force

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

foreach ($p in $presets) {
    $outRows = foreach ($row in $rows) {
        $selected = 'N'
        switch ($row.ItemType) {
            'AuditPolicy' {
                foreach ($prefix in $p.AuditPrefixes) {
                    if ($row.Id.ToUpper().StartsWith($prefix)) { $selected = 'Y'; break }
                }
            }
            'Registry' { if ($p.RegistryIds -contains $row.Id) { $selected = 'Y' } }
            'Channel'  { if ($p.Channels -contains $row.Id) { $selected = 'Y' } }
            # SmbAudit and AD CS items are not addressed by any of these
            # reference baselines and stay deselected.
        }
        $row.Selected = $selected
        $row
    }
    $outFile = Join-Path $OutDir "$($p.Name).csv"
    $outRows | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    $count = @($outRows | Where-Object { $_.Selected -eq 'Y' }).Count
    Write-Host ("{0}  {1} of {2} items selected" -f $outFile, $count, @($outRows).Count)
}

# ---------------------------------------------------------- role presets ---
# Base = the builder's recommended (Core) defaults, then per-role deltas.
# ExtraAudit prefixes: 0CCE922B = Process Creation, 0CCE9226 = Filtering
# Platform Connection.

$rolePresets = @(
    @{ Name = 'role_Workstation';      IncludeDcScope = $false
       ExtraAudit = @('0CCE922B', '0CCE9226')
       ExtraReg   = @('CmdLineAudit', 'ScriptBlock64', 'ScriptBlock32') }
    @{ Name = 'role_MemberServer';     IncludeDcScope = $false
       ExtraAudit = @('0CCE922B')
       ExtraReg   = @('CmdLineAudit', 'ScriptBlock64', 'ScriptBlock32') }
    @{ Name = 'role_DomainController'; IncludeDcScope = $true
       ExtraAudit = @('0CCE922B')
       ExtraReg   = @('CmdLineAudit', 'ScriptBlock64', 'ScriptBlock32') }
)

# Guard against silent selector drift: every role selector must match at
# least one settings-table item, or generation fails (CI runs this on every
# push via the preset drift check).
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
    $outFile = Join-Path $OutDir "$($rp.Name).csv"
    $outRows | Export-Csv -Path $outFile -NoTypeInformation -Encoding UTF8
    $count = @($outRows | Where-Object { $_.Selected -eq 'Y' }).Count
    Write-Host ("{0}  {1} of {2} items selected" -f $outFile, $count, @($outRows).Count)
}

Write-Host ''
Write-Host 'Presets regenerated. Inspect any of them with:'
Write-Host ("  {0} -Show -BaselineFile {1}" -f (Join-Path $kitRoot 'New-LoggingBaseline.ps1'), (Join-Path $OutDir 'role_Workstation.csv'))
exit 0
