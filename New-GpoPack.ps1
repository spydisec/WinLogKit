<#
.SYNOPSIS
    Generates Group Policy delivery artefacts from the settings table (or a
    baseline selection CSV): an advanced audit policy audit.csv and an
    LGPO-format registry.txt, so the GPO can never drift from the tested
    baseline.

.DESCRIPTION
    Output (to -OutDir):
      audit.csv     Advanced audit policy in the CSV format Windows uses for
                    audit policy (auditpol /backup produces the same shape;
                    a GPO carries it as Machine\Microsoft\Windows NT\Audit\
                    audit.csv). Application is driven by the subcategory
                    GUIDs; the name column is informational.
      registry.txt  LGPO.exe text format for the policy-key registry values
                    (PowerShell logging, process command line capture).

    Applying:
      Local / image builds (LGPO.exe from Microsoft's Security Compliance
      Toolkit):
        LGPO.exe /ac .\GPO\audit.csv
        LGPO.exe /t  .\GPO\registry.txt
      Domain GPO: create/edit a GPO whose Advanced Audit Policy Configuration
      matches audit.csv (same subcategory names and values), or use SCT
      tooling to import; the registry values are the ADMX-backed PowerShell
      logging and Audit Process Creation settings under Administrative
      Templates.

    NOT included, by design (printed as reminders):
      - Channel sizes/enablement: no clean GPO mechanism for non-classic
        channels; deliver via startup script or the Intune pack.
      - NTLM audit values (MSV1_0 / Netlogon): these are GPO *Security
        Options* ("Network security: Restrict NTLM: ..."), set them in GPMC.
      - SMB signing/encryption auditing: Set-Smb*Configuration or the
        Server 2025 ADMX.
      - AD CS AuditFilter: CertSvc restart territory, keep it manual.

    Requires: Windows PowerShell 5.1+. No admin; changes nothing on the host.

.PARAMETER BaselineFile
    Selection CSV (New-LoggingBaseline.ps1 or a preset). Without it, tier
    switches decide (Core by default).

.PARAMETER OutDir
    Output folder. Default: .\GPO next to this script.

.EXAMPLE
    .\New-GpoPack.ps1 -IncludeHighVolume
    Core + HighVolume audit policy and registry artefacts.

.EXAMPLE
    .\New-GpoPack.ps1 -BaselineFile .\presets\Microsoft_Server.csv -OutDir .\GPO\MSServer
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
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $PSScriptRoot 'GPO' }

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')

$selection = $null
if (-not [string]::IsNullOrEmpty($BaselineFile)) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile (build one with New-LoggingBaseline.ps1 or use a preset)"
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

$sourceDesc = "Core tier$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
if ($null -ne $selection) { $sourceDesc = "baseline file $(Split-Path $BaselineFile -Leaf)" }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outDirFull = (Resolve-Path $OutDir).Path
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

# ---------------------------------------------------------------- audit.csv ---

$auditLines = New-Object System.Collections.Generic.List[string]
$auditLines.Add('Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value')
$auditCount = 0
foreach ($sub in $script:BaselineAuditSubcategories) {
    if (-not (Test-ItemOn 'AuditPolicy' $sub.Guid $sub.Tier)) { continue }
    $value = 0
    if ($sub.Success) { $value += 1 }
    if ($sub.Failure) { $value += 2 }
    $inclusion = 'No Auditing'
    if ($sub.Success -and $sub.Failure) { $inclusion = 'Success and Failure' }
    elseif ($sub.Success) { $inclusion = 'Success' }
    elseif ($sub.Failure) { $inclusion = 'Failure' }
    # Name column is informational; the GUID drives application.
    $auditLines.Add((',System,Audit {0},{{{1}}},{2},,{3}' -f $sub.Name, $sub.Guid.ToLower(), $inclusion, $value))
    $auditCount++
}
[System.IO.File]::WriteAllText((Join-Path $outDirFull 'audit.csv'), ($auditLines -join "`r`n") + "`r`n", $utf8NoBom)

# -------------------------------------------------------------- registry.txt ---
# LGPO text format: 4 lines per entry (hive scope, key, value name, type:data),
# blank-line separated. Only policy-key values belong here.

$policyPathPattern = '^HKLM:\\SOFTWARE\\(Wow6432Node\\)?Policies\\|^HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\'
$regEntries = New-Object System.Collections.Generic.List[string]
$skipped = New-Object System.Collections.Generic.List[string]
$regCount = 0
foreach ($rs in $script:BaselineRegistrySettings) {
    if (-not (Test-ItemOn 'Registry' $rs.Id $rs.Tier)) { continue }
    if ($rs.Path -notmatch $policyPathPattern) {
        $skipped.Add("$($rs.Path)\$($rs.Name) (GPO Security Options territory - set in GPMC, not a registry.pol value)")
        continue
    }
    $keyPath = $rs.Path -replace '^HKLM:\\', ''
    $typeData = "DWORD:$($rs.Value)"
    if ($rs.Kind -eq 'String') { $typeData = "SZ:$($rs.Value)" }
    $regEntries.Add("Computer`r`n$keyPath`r`n$($rs.Name)`r`n$typeData")
    $regCount++
}
[System.IO.File]::WriteAllText((Join-Path $outDirFull 'registry.txt'), (($regEntries -join "`r`n`r`n") + "`r`n"), $utf8NoBom)

# ------------------------------------------------------------------ output ---

Write-Host "GPO pack written to $outDirFull (from $sourceDesc):" -ForegroundColor Green
Write-Host "  audit.csv     $auditCount audit subcategory rows"
Write-Host "  registry.txt  $regCount policy registry value(s)$(if ($regCount -eq 0) { '  (none selected - PowerShell logging and command line capture are HighVolume/Optional tier)' })"
Write-Host ''
Write-Host 'Apply locally / in image builds (LGPO.exe from the Microsoft Security Compliance Toolkit):' -ForegroundColor White
Write-Host "  LGPO.exe /ac `"$outDirFull\audit.csv`""
Write-Host "  LGPO.exe /t  `"$outDirFull\registry.txt`""
Write-Host 'Domain GPO: mirror audit.csv in Advanced Audit Policy Configuration and the registry values via Administrative Templates.'
if ($skipped.Count -gt 0) {
    Write-Host ''
    Write-Host 'Selected but NOT in this pack (different GPO mechanisms):' -ForegroundColor Yellow
    $skipped | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
Write-Host 'Also not in GPO packs by design: channel sizes/enablement (startup script or Intune pack), SMB auditing (Set-Smb*Configuration), AD CS AuditFilter.' -ForegroundColor Yellow
$totalAudit = @($script:BaselineAuditSubcategories).Count
if ($auditCount -lt $totalAudit) {
    Write-Host ''
    Write-Host ("PARTIAL SELECTION: audit.csv covers {0} of {1} kit subcategories. Apply semantics for the others depend on the tool " -f $auditCount, $totalAudit) -ForegroundColor Yellow
    Write-Host 'and existing policy (LGPO /ac and GPO application may not preserve unlisted subcategories). After applying, ALWAYS verify' -ForegroundColor Yellow
    Write-Host 'the effective result: .\Test-LoggingBaseline.ps1 (it reads the live audit policy, not the file you applied).' -ForegroundColor Yellow
}
Write-Host 'Note: LGPO /t is additive - deselected registry values are NOT removed by a smaller pack. Use Enable-LoggingBaseline -Rollback or remove them deliberately.' -ForegroundColor Yellow
exit 0
