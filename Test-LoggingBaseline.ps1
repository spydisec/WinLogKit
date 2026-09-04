<#
.SYNOPSIS
    Verifies the Windows Server logging baseline. Changes NOTHING.

.DESCRIPTION
    Read-only. Checks, against the shared settings table:
      - each event log channel exists, is enabled where required, is at or
        above the target size, and is not set to "do not overwrite" mode
      - each advanced audit policy subcategory has at least the required
        success/failure auditing (more auditing than required still passes)
      - each registry value is present with the expected data

    Results roll up to a PASS / FAIL / NOT APPLICABLE per Baseline behaviour
    category, printed to the console and written to CSV (detail rows plus a
    category summary). Exit code is non-zero when anything FAILs, so it can
    gate a pipeline.

    HighVolume and Optional tier items are only assessed when the matching
    switch is given - mirroring Enable-LoggingBaseline.ps1 - otherwise they
    report NOT APPLICABLE with the reason, so an undeployed tier does not
    show as a failure. With -BaselineFile, the selection CSV decides instead:
    only Selected = Y items are assessed, so verification always matches
    exactly what was chosen for deployment.

    Requires: Windows PowerShell 5.1+, local Administrator (auditpol needs it).

.PARAMETER IncludeHighVolume
    Assess HighVolume tier items as requirements.

.PARAMETER IncludeOptional
    Assess Optional tier items as requirements.

.PARAMETER BaselineFile
    Path to a selection CSV produced by New-LoggingBaseline.ps1. When given,
    tier switches are ignored and only Selected = Y items are assessed.

.PARAMETER WefRole
    Also check Windows Event Forwarding plumbing for this host's role in a
    WEF deployment. 'Source' checks the SubscriptionManager policy and the
    WinRM service; 'Collector' checks the Wecsvc service, ForwardedEvents
    sizing/retention and that at least one subscription exists. Default:
    None (no WEF checks). WEF rows appear in the detail CSV and affect the
    exit code, but not the per-category rollup.

.PARAMETER OutputDir
    Where the CSVs are written. Default: .\Results next to this script.

.EXAMPLE
    .\Test-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv
    if ($LASTEXITCODE -ne 0) { 'baseline drift detected' }
#>
[CmdletBinding()]
param(
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    [string]$BaselineFile,
    [ValidateSet('None', 'Source', 'Collector')]
    [string]$WefRole = 'None',
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutputDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutputDir)) { $OutputDir = Join-Path $PSScriptRoot 'Results' }

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')
. (Join-Path $PSScriptRoot 'WinLogKit.Common.ps1')

# ---------------------------------------------------------------- helpers ---

# Host probes, registry reads, the audit policy reader and the selection
# model come from WinLogKit.Common.ps1.
$script:Selection = Resolve-BaselineSelection -BaselineFile $BaselineFile -IncludeHighVolume $IncludeHighVolume -IncludeOptional $IncludeOptional

# Returns $null when the item should be assessed, otherwise the
# NOT APPLICABLE reason text.
function Get-SkipReason {
    param([string]$Tier, [string]$ItemType, [string]$Id)
    if ($null -ne $script:Selection.Map) {
        $key = ("$ItemType|$Id").ToUpper()
        if (-not $script:Selection.Map.ContainsKey($key)) { return 'Not listed in baseline file' }
        if (-not $script:Selection.Map[$key]) { return 'Selected = N in baseline file' }
        return $null
    }
    if (Test-ItemSelected $script:Selection $ItemType $Id $Tier) { return $null }
    return "$Tier tier not selected for this assessment"
}

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row {
    param([string[]]$Categories, [string]$ItemType, [string]$Item, [string]$Expected, [string]$Actual, [string]$Result, [string]$Notes = '')
    $rows.Add([pscustomobject]@{
        Categories = ($Categories -join '; ')
        ItemType   = $ItemType
        Item       = $Item
        Expected   = $Expected
        Actual     = $Actual
        Result     = $Result   # PASS | FAIL | NOT APPLICABLE
        Notes      = $Notes
    })
}

# ------------------------------------------------------------------ setup ---

if (-not (Test-IsAdmin)) {
    Write-Error 'Run as local Administrator - reading the audit policy requires it. No changes are ever made.'
    exit 1
}

$domainRole = Get-DomainRole
Write-Host "Test-LoggingBaseline (verification only, nothing is changed)"
Write-Host "Host profile   : $(Get-OsType), $domainRole"
if ($null -ne $script:Selection.Map) {
    Write-Host "Baseline file  : $BaselineFile (tier switches ignored)"
} else {
    Write-Host "Tiers assessed : Core$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
}
Write-Host ''

# ------------------------------------------------------------ channels ------

foreach ($ch in $script:BaselineChannels) {
    $targetMB = [math]::Round($ch.TargetBytes / 1MB)
    $expected = "enabled, >= $targetMB MB, circular retention"
    $skip = Get-SkipReason $ch.Tier 'Channel' $ch.Name
    if ($null -ne $skip) {
        Add-Row $ch.Categories 'Channel' $ch.Name $expected '' 'NOT APPLICABLE' $skip
        continue
    }
    $log = Get-WinEvent -ListLog $ch.Name -ErrorAction SilentlyContinue
    if ($null -eq $log) {
        $note = 'Channel not registered on this host - confirm the owning feature is expected to be absent'
        Add-Row $ch.Categories 'Channel' $ch.Name $expected 'not present' 'NOT APPLICABLE' $note
        continue
    }

    $actualMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
    $problems = @()
    if ($ch.MustEnable -and -not $log.IsEnabled)      { $problems += 'disabled' }
    if ($log.MaximumSizeInBytes -lt $ch.TargetBytes)  { $problems += "size $actualMB MB below target $targetMB MB" }
    if ($log.LogMode -eq 'Retain')                    { $problems += 'retention set to "do not overwrite" - log will stop recording when full' }

    $actual = "enabled=$($log.IsEnabled), $actualMB MB, mode=$($log.LogMode)"
    if ($problems.Count -eq 0) {
        Add-Row $ch.Categories 'Channel' $ch.Name $expected $actual 'PASS'
    } else {
        Add-Row $ch.Categories 'Channel' $ch.Name $expected $actual 'FAIL' ($problems -join '; ')
    }
}

# --------------------------------------------------- audit subcategories ----

$currentAudit = Get-AuditPolicyByGuid
foreach ($sub in $script:BaselineAuditSubcategories) {
    $need = @()
    if ($sub.Success) { $need += 'Success' }
    if ($sub.Failure) { $need += 'Failure' }
    $expected = $need -join ' and '

    if ($sub.Scope -eq 'DomainController' -and $domainRole -ne 'DomainController') {
        Add-Row $sub.Categories 'AuditPolicy' $sub.Name $expected '' 'NOT APPLICABLE' 'Domain controller only - host is not a DC'
        continue
    }
    $skip = Get-SkipReason $sub.Tier 'AuditPolicy' $sub.Guid
    if ($null -ne $skip) {
        Add-Row $sub.Categories 'AuditPolicy' $sub.Name $expected '' 'NOT APPLICABLE' $skip
        continue
    }

    $guid = $sub.Guid.ToUpper()
    $current = 'Unknown'
    if ($currentAudit.ContainsKey($guid)) { $current = $currentAudit[$guid] }

    # Superset passes: required flags must be present; extra auditing is fine.
    # Note: 'Inclusion Setting' text is localised on non-English Windows.
    $hasSuccess = ($current -match 'Success')
    $hasFailure = ($current -match 'Failure')
    $ok = $true
    if ($sub.Success -and -not $hasSuccess) { $ok = $false }
    if ($sub.Failure -and -not $hasFailure) { $ok = $false }

    if ($ok) {
        $note = ''
        if ($current -ne $expected) { $note = 'More auditing than required - accepted' }
        Add-Row $sub.Categories 'AuditPolicy' $sub.Name $expected $current 'PASS' $note
    } else {
        Add-Row $sub.Categories 'AuditPolicy' $sub.Name $expected $current 'FAIL'
    }
}

# ---------------------------------------------------- registry settings -----

foreach ($rs in $script:BaselineRegistrySettings) {
    $label = "$($rs.Path)\$($rs.Name)"
    $expected = "$($rs.Value) ($($rs.Kind))"
    if ($rs.Scope -eq 'DomainController' -and $domainRole -ne 'DomainController') {
        Add-Row $rs.Categories 'Registry' $label $expected '' 'NOT APPLICABLE' 'Domain controller only - host is not a DC'
        continue
    }
    $skip = Get-SkipReason $rs.Tier 'Registry' $rs.Id
    if ($null -ne $skip) {
        Add-Row $rs.Categories 'Registry' $label $expected '' 'NOT APPLICABLE' $skip
        continue
    }

    $current = Get-RegValue -Path $rs.Path -Name $rs.Name
    if ($null -eq $current) {
        Add-Row $rs.Categories 'Registry' $label $expected '<absent>' 'FAIL' 'Value not present'
    } elseif ("$current" -eq "$($rs.Value)") {
        Add-Row $rs.Categories 'Registry' $label $expected "$current" 'PASS'
    } else {
        Add-Row $rs.Categories 'Registry' $label $expected "$current" 'FAIL' 'Value present but wrong data'
    }
}

# ------------------- SMB signing/encryption auditing (Server 2025+) ---------

$smbState = @{}
$srvCfg = $null; $cliCfg = $null
try { $srvCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $srvCfg = $null }
try { $cliCfg = Get-SmbClientConfiguration -ErrorAction Stop } catch { $cliCfg = $null }
foreach ($sa in $script:BaselineSmbAuditSettings) {
    $cfg = $srvCfg
    if ($sa.Side -eq 'Client') { $cfg = $cliCfg }
    if ($null -ne $cfg -and ($cfg.PSObject.Properties.Name -contains $sa.Id)) {
        $smbState[$sa.Id] = [bool]$cfg.($sa.Id)
    }
}
foreach ($sa in $script:BaselineSmbAuditSettings) {
    $expected = "$($sa.Value)"
    $skip = Get-SkipReason $sa.Tier 'SmbAudit' $sa.Id
    if ($null -ne $skip) {
        Add-Row $sa.Categories 'SmbAudit' $sa.Id $expected '' 'NOT APPLICABLE' $skip
        continue
    }
    if (-not $smbState.ContainsKey($sa.Id)) {
        Add-Row $sa.Categories 'SmbAudit' $sa.Id $expected 'unsupported' 'NOT APPLICABLE' 'Requires Windows Server 2025 / Windows 11 24H2 or later'
        continue
    }
    if ($smbState[$sa.Id] -eq $sa.Value) {
        Add-Row $sa.Categories 'SmbAudit' $sa.Id $expected "$($smbState[$sa.Id])" 'PASS'
    } else {
        Add-Row $sa.Categories 'SmbAudit' $sa.Id $expected "$($smbState[$sa.Id])" 'FAIL'
    }
}

# AD CS AuditFilter (conditional on the role being installed)
$af = $script:BaselineAdcsAuditFilter
$activeCa = Get-RegValue -Path $af.BasePath -Name 'Active'
$afSkip = Get-SkipReason $af.Tier 'Registry' $af.Id
if ($null -ne $afSkip) {
    Add-Row $af.Categories 'Registry' 'AD CS AuditFilter' "$($af.Value)" '' 'NOT APPLICABLE' $afSkip
} elseif ([string]::IsNullOrEmpty($activeCa)) {
    Add-Row $af.Categories 'Registry' 'AD CS AuditFilter' "$($af.Value)" '' 'NOT APPLICABLE' 'Certificate Services not installed on this host'
} else {
    $adcsPath = "$($af.BasePath)\$activeCa"
    $current = Get-RegValue -Path $adcsPath -Name $af.Name
    if ("$current" -eq "$($af.Value)") {
        Add-Row $af.Categories 'Registry' "$adcsPath\$($af.Name)" "$($af.Value)" "$current" 'PASS' 'Value only takes effect after a CertSvc restart'
    } else {
        $curText = '<absent>'; if ($null -ne $current) { $curText = "$current" }
        Add-Row $af.Categories 'Registry' "$adcsPath\$($af.Name)" "$($af.Value)" $curText 'FAIL'
    }
}

# ------------------------------- WEF plumbing (optional, role-dependent) ----
# Not part of the behaviour-category model: these verify the transport layer
# set up per the New-WefSubscription.ps1 guidance.

if ($WefRole -eq 'Source') {
    # Value data must actually name a collector (Server=...), not merely exist.
    $smUrls = @()
    $smKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager')
    if ($null -ne $smKey) {
        foreach ($vn in $smKey.GetValueNames()) {
            $vd = "$($smKey.GetValue($vn))"
            if ($vd -match '(?i)Server\s*=\s*http') { $smUrls += $vd }
        }
        $smKey.Close()
    }
    if ($smUrls.Count -gt 0) {
        Add-Row @() 'WEF' 'SubscriptionManager policy' 'at least one Server=<collector URL> value' "$($smUrls.Count) collector URL(s) configured" 'PASS'
    } else {
        Add-Row @() 'WEF' 'SubscriptionManager policy' 'at least one Server=<collector URL> value' 'no valid collector URL' 'FAIL' "Set via GPO: Event Forwarding > Configure target Subscription Manager (Server=http://<collector>:5985/wsman/SubscriptionManager/WEC,Refresh=$($script:BaselineWefDefaults.SubscriptionRefreshSeconds))"  # DevSkim: ignore DS137138 - documented WinRM default; WEF payloads are Kerberos message-level encrypted over HTTP
    }
    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($null -ne $winrm -and $winrm.Status -eq 'Running') {
        Add-Row @() 'WEF' 'WinRM service (source)' 'Running' "$($winrm.Status)" 'PASS'
    } else {
        $state = 'not installed'; if ($null -ne $winrm) { $state = "$($winrm.Status)" }
        Add-Row @() 'WEF' 'WinRM service (source)' 'Running' $state 'FAIL' 'Source-initiated forwarding needs WinRM'
    }
}

if ($WefRole -eq 'Collector') {
    $wec = Get-Service -Name Wecsvc -ErrorAction SilentlyContinue
    if ($null -ne $wec -and $wec.Status -eq 'Running') {
        Add-Row @() 'WEF' 'Windows Event Collector service' 'Running' "$($wec.Status)" 'PASS'
    } else {
        $state = 'not installed'; if ($null -ne $wec) { $state = "$($wec.Status)" }
        Add-Row @() 'WEF' 'Windows Event Collector service' 'Running' $state 'FAIL' 'Run: wecutil qc /q'
    }
    # Wecsvc alone is not enough: sources connect to the WinRM listener.
    # Try HTTP first, then HTTPS, so an HTTPS-only listener still passes.
    $listenerVia = ''
    try { Test-WSMan -ErrorAction Stop | Out-Null; $listenerVia = 'HTTP' } catch {
        try { Test-WSMan -UseSSL -ErrorAction Stop | Out-Null; $listenerVia = 'HTTPS' } catch { $listenerVia = '' }
    }
    if ($listenerVia -ne '') {
        Add-Row @() 'WEF' 'WinRM listener (collector)' 'responding (HTTP or HTTPS)' "responding ($listenerVia)" 'PASS'
    } else {
        Add-Row @() 'WEF' 'WinRM listener (collector)' 'responding (HTTP or HTTPS)' 'not responding' 'FAIL' 'Run: winrm qc -q (sources cannot connect without a WinRM listener)'
    }
    $fwdMin = $script:BaselineWefDefaults.ForwardedEventsMinBytes
    $fwdRec = [math]::Round($script:BaselineWefDefaults.ForwardedEventsRecommendedBytes / 1MB)
    $fwd = Get-WinEvent -ListLog ForwardedEvents -ErrorAction SilentlyContinue
    if ($null -ne $fwd) {
        $fwdMB = [math]::Round($fwd.MaximumSizeInBytes / 1MB)
        $fwdProblems = @()
        if ($fwd.MaximumSizeInBytes -lt $fwdMin) { $fwdProblems += "size $fwdMB MB below $([math]::Round($fwdMin/1MB)) MB minimum ($fwdRec MB recommended for collectors)" }
        if ($fwd.LogMode -eq 'Retain') { $fwdProblems += 'retention set to "do not overwrite"' }
        if ($fwdProblems.Count -eq 0) {
            Add-Row @() 'WEF' 'ForwardedEvents log' (">= $([math]::Round($fwdMin/1MB)) MB, circular") "$fwdMB MB, mode=$($fwd.LogMode)" 'PASS'
        } else {
            Add-Row @() 'WEF' 'ForwardedEvents log' (">= $([math]::Round($fwdMin/1MB)) MB, circular") "$fwdMB MB, mode=$($fwd.LogMode)" 'FAIL' ($fwdProblems -join '; ')
        }
    } else {
        Add-Row @() 'WEF' 'ForwardedEvents log' (">= $([math]::Round($fwdMin/1MB)) MB, circular") 'not present' 'FAIL' 'Windows Event Collector not configured'
    }
    $subs = @(& wecutil es 2>$null | Where-Object { $_ -match '\S' })
    if ($LASTEXITCODE -eq 0 -and $subs.Count -gt 0) {
        Add-Row @() 'WEF' 'Collector subscriptions' 'at least one subscription' ($subs -join '; ') 'PASS'
    } else {
        Add-Row @() 'WEF' 'Collector subscriptions' 'at least one subscription' 'none' 'FAIL' 'Load one: wecutil cs <subscription.xml> (generate with New-WefSubscription.ps1)'
    }
}

# --------------------------------------------------- per-category rollup ----
# FAIL if any member item fails; PASS if at least one item passes and none
# fail; NOT APPLICABLE when every member item is NOT APPLICABLE.

$summary = New-Object System.Collections.Generic.List[object]
foreach ($cat in $script:BaselineCategories) {
    $catRows = @($rows | Where-Object { ($_.Categories -split '; ') -contains $cat })
    $failCount = @($catRows | Where-Object { $_.Result -eq 'FAIL' }).Count
    $passCount = @($catRows | Where-Object { $_.Result -eq 'PASS' }).Count

    if ($failCount -gt 0)     { $catResult = 'FAIL' }
    elseif ($passCount -gt 0) { $catResult = 'PASS' }
    else                      { $catResult = 'NOT APPLICABLE' }

    $summary.Add([pscustomobject]@{
        Category = $cat
        Result   = $catResult
        Pass     = $passCount
        Fail     = $failCount
        NA       = @($catRows | Where-Object { $_.Result -eq 'NOT APPLICABLE' }).Count
        CoverageNote = $script:BaselineCategoryNotes[$cat]
    })
}

Write-Host '=== Per-category results ===' -ForegroundColor White
foreach ($s in $summary) {
    $colour = 'Green'
    if ($s.Result -eq 'FAIL') { $colour = 'Red' }
    if ($s.Result -eq 'NOT APPLICABLE') { $colour = 'DarkGray' }
    Write-Host ('{0,-16} {1,-32} pass={2} fail={3} n/a={4}' -f $s.Result, $s.Category, $s.Pass, $s.Fail, $s.NA) -ForegroundColor $colour
}

# ---------------------------------------------------------------- output ----

if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$detailCsv  = Join-Path $OutputDir "Test-LoggingBaseline_Detail_$stamp.csv"
$summaryCsv = Join-Path $OutputDir "Test-LoggingBaseline_Summary_$stamp.csv"
$rows    | Export-Csv -Path $detailCsv  -NoTypeInformation -Encoding UTF8
$summary | Export-Csv -Path $summaryCsv -NoTypeInformation -Encoding UTF8

$totalFail = @($rows | Where-Object { $_.Result -eq 'FAIL' }).Count
Write-Host ''
Write-Host "Detail CSV  : $detailCsv"
Write-Host "Summary CSV : $summaryCsv"
Write-Host ''
if ($totalFail -gt 0) {
    Write-Host "RESULT: FAIL - $totalFail item(s) below baseline." -ForegroundColor Red
    exit 1
} else {
    Write-Host 'RESULT: PASS - all assessed items meet the baseline.' -ForegroundColor Green
    exit 0
}
