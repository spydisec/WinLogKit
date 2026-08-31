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
# Exclusions apply to the path RELATIVE to the kit root, so a kit that itself
# lives under e.g. C:\staging\WELA-2.1.0\kit is not silently skipped entirely.
# WELA[^\\]* also skips unzipped release folders like WELA-2.1.0 (third-party code).
$kitRootFull = (Resolve-Path $KitRoot).Path.TrimEnd('\')
$parsed = 0
foreach ($f in Get-ChildItem $KitRoot -Filter *.ps1 -Recurse | Where-Object { $_.FullName.Substring($kitRootFull.Length) -notmatch '\\(WELA[^\\]*|Baseline|Logs|Results|Evidence|Intune)\\' }) {
    $parsed++
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Fail "$($f.Name) has parse errors: $($errors[0].Message) (line $($errors[0].Extent.StartLineNumber))"
    } else {
        Pass "parse $($f.Name)"
    }
}

if ($parsed -eq 0) { Fail 'parse loop matched zero files - exclusion filter is over-matching' }

# 1b. Registry-write safety tripwire. WELA issue #243: New-Item -Force on an
# existing registry key WIPES its other values (it broke Netlogon on DCs).
# The kit writes registry exclusively via [Microsoft.Win32.Registry]::SetValue.
# AST-based rule, robust against variable paths: every New-Item invocation in
# the kit must declare -ItemType Directory (or File) explicitly - a New-Item
# without it could be a registry key creation and fails the check.
$badNewItem = @()
foreach ($f in Get-ChildItem $KitRoot -Filter *.ps1 -Recurse |
    Where-Object { $_.FullName.Substring($kitRootFull.Length) -notmatch '\\(WELA[^\\]*|Baseline|Logs|Results|Evidence|Intune)\\' }) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
    $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Item' }, $true)
    foreach ($c in $calls) {
        $elems = @($c.CommandElements | ForEach-Object { $_.Extent.Text })
        $itIdx = [array]::IndexOf($elems, '-ItemType')
        $ok = ($itIdx -ge 0 -and $itIdx + 1 -lt $elems.Count -and $elems[$itIdx + 1] -match '^(Directory|File)$')
        if (-not $ok) { $badNewItem += "$($f.Name):$($c.Extent.StartLineNumber)" }
    }
}
if ($badNewItem) {
    Fail "New-Item without explicit -ItemType Directory/File (could create a registry key and wipe sibling values, WELA issue #243 class): $($badNewItem -join ', ')"
} else {
    Pass 'every New-Item declares -ItemType Directory/File (WELA issue #243 class fenced)'
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

    # 5. Intune pack generation: files parse, placeholders replaced, selection respected
    $packDir = Join-Path $tmp 'intune'
    & (Join-Path $KitRoot 'New-IntuneRemediationPack.ps1') -OutDir $packDir | Out-Null
    foreach ($f in @('Detect-LoggingBaseline.ps1', 'Remediate-LoggingBaseline.ps1')) {
        $p = Join-Path $packDir $f
        if (-not (Test-Path $p)) { Fail "Intune pack missing $f"; continue }
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$tokens, [ref]$errors) | Out-Null
        if ($errors.Count -gt 0) { Fail "generated $f has parse errors: $($errors[0].Message)" } else { Pass "generated $f parses" }
        if ((Get-Content $p -Raw) -match '__(MODE|ITEMS|COUNT|SOURCE|FILENAME)__') { Fail "generated $f has unreplaced placeholders" }
    }
    $packDir2 = Join-Path $tmp 'intune-csv'
    & (Join-Path $KitRoot 'New-IntuneRemediationPack.ps1') -OutDir $packDir2 -BaselineFile $csv1 | Out-Null
    $detect2 = Get-Content (Join-Path $packDir2 'Detect-LoggingBaseline.ps1') -Raw
    # The recommended CSV selects only Core, so no HighVolume item may be embedded.
    if ($detect2 -match 'EnableModuleLogging') { Fail 'Intune pack from Core-only CSV embedded a HighVolume item' } else { Pass 'Intune pack honours the baseline CSV selection' }

    # 6. Presets: committed CSVs must match what the generator produces
    $presetTmp = Join-Path $tmp 'presets'
    & (Join-Path $KitRoot 'tools\New-PresetBaselines.ps1') -OutDir $presetTmp | Out-Null
    foreach ($name in @('ASD', 'Microsoft_Client', 'Microsoft_Server', 'role_Workstation', 'role_MemberServer', 'role_DomainController', 'spydi_Workstation_Minimal', 'spydi_Workstation_Heavy', 'spydi_Server_Minimal', 'spydi_Server_Heavy')) {
        $committed = Join-Path $KitRoot "presets\$name.csv"
        if (-not (Test-Path $committed)) { Fail "presets\$name.csv is missing - run tools\New-PresetBaselines.ps1"; continue }
        # Compare ALL columns, so descriptive fields (Purpose, Risk, Tier...)
        # in committed presets cannot go stale while the check passes.
        $rowKey = { ($_.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '|' }
        $a = Import-Csv $committed | ForEach-Object $rowKey | Sort-Object
        $b = Import-Csv (Join-Path $presetTmp "$name.csv") | ForEach-Object $rowKey | Sort-Object
        if (Compare-Object $a $b) { Fail "presets\$name.csv drifted from the generator - rerun tools\New-PresetBaselines.ps1" } else { Pass "preset $name matches generator" }
    }

    # 7a. GPO pack: audit.csv row count matches selection; registry.txt has policy values
    $gpoTmp = Join-Path $tmp 'gpo'
    & (Join-Path $KitRoot 'New-GpoPack.ps1') -OutDir $gpoTmp -IncludeHighVolume | Out-Null
    $auditRows = @(Import-Csv (Join-Path $gpoTmp 'audit.csv'))
    $expectedAudit = @($BaselineAuditSubcategories | Where-Object { $_.Tier -eq 'Core' -or $_.Tier -eq 'HighVolume' }).Count
    if ($auditRows.Count -eq $expectedAudit) { Pass "GPO audit.csv rows ($expectedAudit)" } else { Fail "GPO audit.csv has $($auditRows.Count) rows, expected $expectedAudit" }
    if ((Get-Content (Join-Path $gpoTmp 'registry.txt') -Raw) -match 'EnableScriptBlockLogging') { Pass 'GPO registry.txt contains expected policy value' } else { Fail 'GPO registry.txt missing EnableScriptBlockLogging' }

    # 7b. ATT&CK native mapping: event map integrity, then join sanity
    $badMap = @()
    foreach ($m in (Import-Csv (Join-Path $KitRoot 'data\attack\event_map.csv'))) {
        if ($m.item_type -eq 'AuditPolicy' -and $m.item_id -ne '' -and
            -not @($BaselineAuditSubcategories | Where-Object { $_.Guid.ToUpper() -eq $m.item_id.ToUpper() }).Count) {
            $badMap += "GUID $($m.item_id)"
        }
        if ($m.item_type -eq 'Channel' -and $m.item_id -ne '' -and
            -not @($BaselineChannels | Where-Object { $_.Name -eq $m.item_id }).Count) {
            $badMap += "channel $($m.item_id)"
        }
    }
    if ($badMap) { Fail "event_map.csv references unknown settings items: $($badMap -join ', ')" } else { Pass 'event map item ids valid against settings table' }

    $covTmp = Join-Path $tmp 'cov'
    & (Join-Path $KitRoot 'Export-AttackCoverage.ps1') -OutDir $covTmp | Out-Null
    $covDetail = Get-ChildItem $covTmp -Filter 'AttackCoverage_Detail_*.csv' | Select-Object -First 1
    if ($null -eq $covDetail) { Fail 'coverage detail CSV not produced' } else {
        $covRows = Import-Csv $covDetail.FullName
        $obs = @($covRows | Where-Object { $_.Status -eq 'Observable' }).Count
        # Core-tier native-mapping sanity: ~1480 analytic rows, ~199 of them
        # observable at Core (measured at snapshot time); Sysmon-only rows
        # dominate the non-observable share by design.
        if ($covRows.Count -gt 1400 -and $obs -ge 150) { Pass "ATT&CK native coverage joins ($($covRows.Count) rows, $obs observable)" } else { Fail "ATT&CK coverage looks wrong ($($covRows.Count) rows, $obs observable)" }
    }

    # 7. WEF subscription generation: valid XML, one query per selected channel
    $wefTmp = Join-Path $tmp 'wef'
    & (Join-Path $KitRoot 'New-WefSubscription.ps1') -OutDir $wefTmp -BaselineFile (Join-Path $KitRoot 'presets\ASD.csv') -SubscriptionId 'CheckSub' | Out-Null
    try {
        [xml]$wx = Get-Content (Join-Path $wefTmp 'CheckSub.xml') -Raw
        $qCount = [regex]::Matches($wx.Subscription.Query.'#cdata-section', '<Query ').Count
        if ($qCount -eq 3) { Pass 'WEF subscription XML valid (3 queries for the ASD preset)' } else { Fail "WEF XML has $qCount queries, expected 3 for the ASD preset" }
    } catch { Fail "WEF subscription XML invalid: $($_.Exception.Message)" }
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
