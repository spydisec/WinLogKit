<#
.SYNOPSIS
    Generates a self-contained Intune remediation pair (detection +
    remediation script) from the kit's settings table, optionally filtered by
    a New-LoggingBaseline.ps1 selection CSV.

.DESCRIPTION
    Intune Remediations upload single standalone .ps1 files, so the generated
    scripts embed everything they need - no settings file, no kit folder, no
    network access on the endpoint. The settings table stays the single
    source of truth: regenerate the pack whenever the table or your baseline
    selection changes.

    Output (to -OutDir):
      Detect-LoggingBaseline.ps1     exit 0 = compliant, exit 1 = non-compliant
                                     (with a one-line summary Intune displays)
      Remediate-LoggingBaseline.ps1  applies the embedded baseline, exit 0 on
                                     success, exit 1 if any item errored

    Generated-script behaviour on the endpoint:
      - Domain-controller-only items are skipped at runtime on non-DCs.
      - Channels not registered on the host are skipped (feature absent).
      - Server 2025 SMB audit items are skipped where the OS lacks them.
      - Remediation only touches items that are actually below baseline
        (idempotent), never shrinks a log, never reboots or restarts services.
      - The AD CS AuditFilter is deliberately EXCLUDED from packs: it needs a
        CertSvc restart, which does not belong in an unattended remediation.

    Intune deployment (Devices > Scripts and remediations > Create):
      - Run this script using the logged-on credentials: No  (runs as SYSTEM)
      - Run script in 64-bit PowerShell: Yes
      - Enforce script signature check: per your org's policy

    Requires: Windows PowerShell 5.1+. No admin needed to generate.

.PARAMETER OutDir
    Where to write the pair. Default: .\Intune next to this script.

.PARAMETER BaselineFile
    Optional selection CSV from New-LoggingBaseline.ps1. Only Selected = Y
    items are embedded. Without it, the recommended set is used (Core, plus
    HighVolume/Optional tiers if the matching switches are given).

.PARAMETER IncludeHighVolume
    Without -BaselineFile: also embed HighVolume tier items.

.PARAMETER IncludeOptional
    Without -BaselineFile: also embed Optional tier items.

.EXAMPLE
    .\New-IntuneRemediationPack.ps1
    Recommended (Core) pack into .\Intune\.

.EXAMPLE
    .\New-IntuneRemediationPack.ps1 -BaselineFile .\WorkstationBaseline.csv -OutDir .\Intune\Workstation
    Pack for a role-specific baseline built with New-LoggingBaseline.ps1.
#>
[CmdletBinding()]
param(
    # Defaults resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutDir,
    [string]$BaselineFile,
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $PSScriptRoot 'Intune' }

# Captured here so the nested Test-Wanted function reads script-level state
# (also keeps PSScriptAnalyzer's unused-parameter analysis accurate).
$wantHighVolume = [bool]$IncludeHighVolume
$wantOptional   = [bool]$IncludeOptional

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')

# ---------------------------------------------------------- item selection ---

$selection = $null
if (-not [string]::IsNullOrEmpty($BaselineFile)) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile (build one with New-LoggingBaseline.ps1)"
        exit 1
    }
    $selection = @{}
    foreach ($row in (Import-Csv $BaselineFile)) {
        $selection[("$($row.ItemType)|$($row.Id)").ToUpper()] = ("$($row.Selected)".Trim() -match '^(Y|YES|TRUE|1)$')
    }
}

function Test-Wanted {
    param([string]$ItemType, [string]$Id, [string]$Tier)
    if ($null -ne $selection) {
        $key = ("$ItemType|$Id").ToUpper()
        return ($selection.ContainsKey($key) -and $selection[$key])
    }
    if ($Tier -eq 'Core') { return $true }
    if ($Tier -eq 'HighVolume') { return $script:wantHighVolume }
    if ($Tier -eq 'Optional') { return $script:wantOptional }
    return $false
}

# ------------------------------------------- build the embedded item table ---

function ConvertTo-PsString { param([string]$s) "'" + ($s -replace "'", "''") + "'" }
function ConvertTo-PsBool   { param([bool]$b) if ($b) { '$true' } else { '$false' } }

$lines = New-Object System.Collections.Generic.List[string]

foreach ($ch in $script:BaselineChannels) {
    if (-not (Test-Wanted 'Channel' $ch.Name $ch.Tier)) { continue }
    $lines.Add(('    @{{ Type=''Channel''; Name={0}; TargetBytes={1}; MustEnable={2}; DCOnly=$false }}' -f `
        (ConvertTo-PsString $ch.Name), $ch.TargetBytes, (ConvertTo-PsBool $ch.MustEnable)))
}
foreach ($sub in $script:BaselineAuditSubcategories) {
    if (-not (Test-Wanted 'AuditPolicy' $sub.Guid $sub.Tier)) { continue }
    $lines.Add(('    @{{ Type=''AuditPolicy''; Name={0}; Guid={1}; Success={2}; Failure={3}; DCOnly={4} }}' -f `
        (ConvertTo-PsString $sub.Name), (ConvertTo-PsString $sub.Guid.ToUpper()), `
        (ConvertTo-PsBool $sub.Success), (ConvertTo-PsBool $sub.Failure), `
        (ConvertTo-PsBool ($sub.Scope -eq 'DomainController'))))
}
foreach ($rs in $script:BaselineRegistrySettings) {
    if (-not (Test-Wanted 'Registry' $rs.Id $rs.Tier)) { continue }
    $valueLiteral = $rs.Value
    if ($rs.Kind -eq 'String') { $valueLiteral = ConvertTo-PsString "$($rs.Value)" }
    $lines.Add(('    @{{ Type=''Registry''; Path={0}; Name={1}; Kind={2}; Value={3}; DCOnly={4} }}' -f `
        (ConvertTo-PsString $rs.Path), (ConvertTo-PsString $rs.Name), (ConvertTo-PsString $rs.Kind), `
        $valueLiteral, (ConvertTo-PsBool ($rs.Scope -eq 'DomainController'))))
}
foreach ($sa in $script:BaselineSmbAuditSettings) {
    if (-not (Test-Wanted 'SmbAudit' $sa.Id $sa.Tier)) { continue }
    $lines.Add(('    @{{ Type=''SmbAudit''; Id={0}; Side={1}; Value={2}; DCOnly=$false }}' -f `
        (ConvertTo-PsString $sa.Id), (ConvertTo-PsString $sa.Side), (ConvertTo-PsBool $sa.Value)))
}

if ($lines.Count -eq 0) {
    Write-Error 'No items selected - nothing to generate.'
    exit 1
}

$sourceDesc = 'recommended tiers'
if ($null -ne $selection) { $sourceDesc = "baseline file $(Split-Path $BaselineFile -Leaf)" }

# ----------------------------------------------------------- the template ---
# Single-quoted here-string: everything is literal; placeholders are replaced
# below. The generated code is Windows PowerShell 5.1 compatible and safe to
# run as SYSTEM (no profile, no prompts, no files written).

$template = @'
# __FILENAME__ - generated by WinLogKit New-IntuneRemediationPack.ps1
# Source: __SOURCE__ | Items: __COUNT__ | Kit: https://github.com/spydisec/WinLogKit
# Do not edit by hand - regenerate from the kit so the pack matches the tested baseline.
# Intune settings: run as SYSTEM (logged-on credentials: No), 64-bit PowerShell: Yes.

$Mode = '__MODE__'
$ErrorActionPreference = 'Stop'

$Items = @(
__ITEMS__
)

function Get-RegVal { param([string]$Path, [string]$Name)
    [Microsoft.Win32.Registry]::GetValue(($Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'), $Name, $null)
}
function Set-RegVal { param([string]$Path, [string]$Name, $Value, [string]$Kind)
    [Microsoft.Win32.Registry]::SetValue(($Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\'), $Name, $Value, [Microsoft.Win32.RegistryValueKind]::$Kind)
}

$isDc = ((Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole -ge 4)

$auditMap = @{}
auditpol /get /category:* /r | Where-Object { $_ -match '\S' } | ConvertFrom-Csv | ForEach-Object {
    $auditMap[(($_.'Subcategory GUID') -replace '[{}]', '').ToUpper()] = $_.'Inclusion Setting'
}

$srvCfg = $null; $cliCfg = $null
try { $srvCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $srvCfg = $null }
try { $cliCfg = Get-SmbClientConfiguration -ErrorAction Stop } catch { $cliCfg = $null }

$failList = New-Object System.Collections.Generic.List[string]
$checked = 0; $fixed = 0; $errorCount = 0

foreach ($i in $Items) {
    try {
        if ($i.DCOnly -and -not $isDc) { continue }
        switch ($i.Type) {
            'Channel' {
                $log = Get-WinEvent -ListLog $i.Name -ErrorAction SilentlyContinue
                if ($null -eq $log) { continue }   # channel/feature absent on this host
                $checked++
                $needSize   = ($log.MaximumSizeInBytes -lt $i.TargetBytes)
                $needEnable = ($i.MustEnable -and -not $log.IsEnabled)
                if ($needSize -or $needEnable) {
                    if ($Mode -eq 'Detect') {
                        $failList.Add("Channel:$($i.Name)")
                    } else {
                        if ($needSize)   { wevtutil sl "$($i.Name)" /ms:$($i.TargetBytes) 2>&1 | Out-Null }
                        if ($needEnable) { wevtutil sl "$($i.Name)" /e:true 2>&1 | Out-Null }
                        $fixed++
                    }
                }
            }
            'AuditPolicy' {
                $checked++
                $cur = ''
                if ($auditMap.ContainsKey($i.Guid)) { $cur = $auditMap[$i.Guid] }
                $ok = $true
                if ($i.Success -and $cur -notmatch 'Success') { $ok = $false }
                if ($i.Failure -and $cur -notmatch 'Failure') { $ok = $false }
                if (-not $ok) {
                    if ($Mode -eq 'Detect') {
                        $failList.Add("Audit:$($i.Name)")
                    } else {
                        $s = 'disable'; if ($i.Success) { $s = 'enable' }
                        $f = 'disable'; if ($i.Failure) { $f = 'enable' }
                        auditpol /set /subcategory:"{$($i.Guid)}" /success:$s /failure:$f | Out-Null
                        if ($LASTEXITCODE -ne 0) { throw "auditpol exit code $LASTEXITCODE" }
                        $fixed++
                    }
                }
            }
            'Registry' {
                $checked++
                $cur = Get-RegVal -Path $i.Path -Name $i.Name
                if ("$cur" -ne "$($i.Value)") {
                    if ($Mode -eq 'Detect') {
                        $failList.Add("Reg:$($i.Name)")
                    } else {
                        Set-RegVal -Path $i.Path -Name $i.Name -Value $i.Value -Kind $i.Kind
                        $fixed++
                    }
                }
            }
            'SmbAudit' {
                $cfg = $srvCfg
                if ($i.Side -eq 'Client') { $cfg = $cliCfg }
                if ($null -eq $cfg -or -not ($cfg.PSObject.Properties.Name -contains $i.Id)) { continue }   # pre-2025 OS
                $checked++
                if ([bool]$cfg.($i.Id) -ne $i.Value) {
                    if ($Mode -eq 'Detect') {
                        $failList.Add("Smb:$($i.Id)")
                    } else {
                        $p = @{ $i.Id = $i.Value; Force = $true }
                        if ($i.Side -eq 'Server') { Set-SmbServerConfiguration @p } else { Set-SmbClientConfiguration @p }
                        $fixed++
                    }
                }
            }
        }
    } catch {
        $errorCount++
        $failList.Add("Error:$($i.Type):$($_.Exception.Message)")
    }
}

if ($Mode -eq 'Detect') {
    if ($failList.Count -eq 0) {
        Write-Output "COMPLIANT: $checked applicable settings meet the baseline"
        exit 0
    }
    $top = (@($failList) | Select-Object -First 8) -join '; '
    Write-Output "NONCOMPLIANT: $($failList.Count) of $checked below baseline: $top"
    exit 1
} else {
    Write-Output "REMEDIATED: $fixed change(s) applied across $checked applicable settings, $errorCount error(s)"
    if ($errorCount -gt 0) { exit 1 }
    exit 0
}
'@

# ------------------------------------------------------------ write output ---

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$itemsBlock = $lines -join "`r`n"

foreach ($mode in @('Detect', 'Remediate')) {
    $fileName = "$mode-LoggingBaseline.ps1"
    $content = $template.
        Replace('__FILENAME__', $fileName).
        Replace('__SOURCE__', $sourceDesc).
        Replace('__COUNT__', "$($lines.Count)").
        Replace('__MODE__', $mode).
        Replace('__ITEMS__', $itemsBlock)
    Set-Content -Path (Join-Path $OutDir $fileName) -Value $content -Encoding UTF8
}

Write-Host "Intune remediation pack written to $OutDir ($($lines.Count) items, from $sourceDesc):" -ForegroundColor Green
Write-Host '  Detect-LoggingBaseline.ps1     (detection: exit 0 compliant / 1 non-compliant)'
Write-Host '  Remediate-LoggingBaseline.ps1  (remediation: applies the embedded baseline)'
Write-Host ''
Write-Host 'Excluded by design: AD CS AuditFilter (needs a CertSvc restart - not for unattended remediation).' -ForegroundColor Yellow
Write-Host 'Upload both in Intune: Devices > Scripts and remediations > Create. Run as SYSTEM, 64-bit: Yes.'
exit 0
