<#
.SYNOPSIS
    Kit self-checks, runnable locally and in CI. Exits non-zero on any failure.

.DESCRIPTION
    Safe on any machine: nothing is applied, no admin needed. Checks:
      1. Every .ps1 parses cleanly on the current PowerShell engine
         (CI runs this under both Windows PowerShell 5.1 and PowerShell 7).
      2. The settings table is internally consistent: category tags valid,
         coverage notes complete, audit GUIDs unique and well-formed.
      3. New-LoggingBaseline.ps1 runs end-to-end non-interactively and its
         CSV round-trips against every ID the enable/test scripts look up.
      4. Recommended defaults select exactly the Core tier.
#>
[CmdletBinding()]
param(
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$KitRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($KitRoot)) { $KitRoot = Split-Path $PSScriptRoot -Parent }
$failures = 0

function Fail { param([string]$Msg) Write-Host "FAIL: $Msg" -ForegroundColor Red; $script:failures++ }
function Pass { param([string]$Msg) Write-Host "PASS: $Msg" -ForegroundColor Green }

Write-Host "Kit checks on PowerShell $($PSVersionTable.PSVersion) - root: $KitRoot"

# 1. Parse every script -------------------------------------------------------
foreach ($f in Get-ChildItem $KitRoot -Filter *.ps1 -Recurse | Where-Object { $_.FullName -notmatch '\\(WELA|Baseline|Logs|Results|Evidence)\\' }) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Fail "$($f.Name) has parse errors: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))"
    } else {
        Pass "parse $($f.Name)"
    }
}

# 2. Settings table consistency -----------------------------------------------
. (Join-Path $KitRoot 'LoggingBaseline.Settings.ps1')

$bad = @()
foreach ($grp in @($BaselineChannels, $BaselineAuditSubcategories, $BaselineRegistrySettings, $BaselineSmbAuditSettings)) {
    foreach ($item in $grp) {
        foreach ($c in $item.Categories) {
            if ($BaselineCategories -notcontains $c) { $bad += "'$c'" }
        }
    }
}
foreach ($c in $BaselineAdcsAuditFilter.Categories) { if ($BaselineCategories -notcontains $c) { $bad += "'$c'" } }
if ($bad) { Fail "unknown category tags: $($bad -join ', ')" } else { Pass 'category tags all valid' }

$noteMissing = @($BaselineCategories | Where-Object { -not $BaselineCategoryNotes.ContainsKey($_) })
if ($noteMissing) { Fail "missing coverage notes: $($noteMissing -join ', ')" } else { Pass 'coverage notes complete' }

$guids = @($BaselineAuditSubcategories | ForEach-Object { $_.Guid.ToUpper() })
if (@($guids | Sort-Object -Unique).Count -ne $guids.Count) { Fail 'duplicate audit subcategory GUIDs' } else { Pass 'audit GUIDs unique' }
$badGuid = @($guids | Where-Object { $_ -notmatch '^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$' })
if ($badGuid) { Fail "malformed GUIDs: $($badGuid -join ', ')" } else { Pass 'audit GUIDs well-formed' }

# 3. Builder end-to-end + CSV round-trip --------------------------------------
$tmp = Join-Path ([IO.Path]::GetTempPath()) "winlogkit-checks-$PID"
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $csv1 = Join-Path $tmp 'recommended.csv'
    $csv2 = Join-Path $tmp 'all-tiers.csv'
    & (Join-Path $KitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -OutFile $csv1 -Force | Out-Null
    & (Join-Path $KitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -IncludeHighVolume -IncludeOptional -OutFile $csv2 -Force | Out-Null

    $r1 = Import-Csv $csv1
    $r2 = Import-Csv $csv2

    $expectedCount = $BaselineChannels.Count + $BaselineAuditSubcategories.Count + $BaselineRegistrySettings.Count + $BaselineSmbAuditSettings.Count + 1
    if ($r1.Count -ne $expectedCount) { Fail "builder CSV has $($r1.Count) rows, expected $expectedCount" } else { Pass "builder CSV row count ($expectedCount)" }

    $csvKeys = @{}
    foreach ($row in $r1) { $csvKeys[("$($row.ItemType)|$($row.Id)").ToUpper()] = $true }
    $missing = @()
    foreach ($ch in $BaselineChannels)          { $k = ("Channel|$($ch.Name)").ToUpper();     if (-not $csvKeys[$k]) { $missing += $k } }
    foreach ($s in $BaselineAuditSubcategories) { $k = ("AuditPolicy|$($s.Guid)").ToUpper();  if (-not $csvKeys[$k]) { $missing += $k } }
    foreach ($rs in $BaselineRegistrySettings)  { $k = ("Registry|$($rs.Id)").ToUpper();      if (-not $csvKeys[$k]) { $missing += $k } }
    foreach ($sa in $BaselineSmbAuditSettings)  { $k = ("SmbAudit|$($sa.Id)").ToUpper();      if (-not $csvKeys[$k]) { $missing += $k } }
    $k = ("Registry|$($BaselineAdcsAuditFilter.Id)").ToUpper(); if (-not $csvKeys[$k]) { $missing += $k }
    if ($missing) { Fail "CSV round-trip missing keys: $($missing -join ', ')" } else { Pass 'CSV round-trips every lookup key' }

    # 4. Recommended defaults = exactly the Core tier -------------------------
    $coreCount = @($r1 | Where-Object { $_.Tier -eq 'Core' }).Count
    $selCore   = @($r1 | Where-Object { $_.Selected -eq 'Y' -and $_.Tier -eq 'Core' }).Count
    $selOther  = @($r1 | Where-Object { $_.Selected -eq 'Y' -and $_.Tier -ne 'Core' }).Count
    if ($selCore -ne $coreCount -or $selOther -ne 0) { Fail "recommended defaults wrong (core=$coreCount selected-core=$selCore selected-noncore=$selOther)" } else { Pass 'recommended defaults select exactly Core' }
    if (@($r2 | Where-Object { $_.Selected -eq 'Y' }).Count -ne $r2.Count) { Fail 'all-tiers run did not select everything' } else { Pass 'all-tiers run selects everything' }
}
finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
if ($failures -gt 0) {
    Write-Host "$failures check(s) failed." -ForegroundColor Red
    exit 1
}
Write-Host 'All kit checks passed.' -ForegroundColor Green
exit 0
