<#
.SYNOPSIS
    Enables the Windows logging baseline on a server or endpoint (event log channels,
    advanced audit policy subcategories and registry settings) derived from
    the Yamato Security EnableWindowsLogSettings / WELA baselines.

.DESCRIPTION
    Idempotent - safe to run repeatedly. Every item is compared to its target
    first; already-correct items are reported and left alone.

    Two ways to choose what gets applied:

    1. Tier switches (simple):
      Core        applied by default.
      HighVolume  material event volume / performance impact, or only useful
                  in some environments. NOT applied unless -IncludeHighVolume
                  is given - listed as PENDING DECISION so a human chooses.

    2. A custom baseline file (precise): build a selection CSV with
       New-LoggingBaseline.ps1 (interactively, or -AcceptRecommended then edit
       in Excel) and pass it via -BaselineFile. Only items with Selected = Y
       are applied; everything else is reported as excluded. Tier switches are
       ignored in this mode - the file IS the decision.

    Backups are automatic and happen BEFORE any change:
      - First real (non -WhatIf) run: the complete pre-kit state (full
        audit policy backup, channel sizes/enablement, registry values
        including absence, SMB audit settings) is captured to .\Baseline\.
        -Rollback always restores this state - "undo the kit entirely".
      - Every later real run: a timestamped pre-change snapshot of the
        CURRENT state is saved to .\Baseline\snapshots\<timestamp>\ (same
        contents), so stepping between baselines leaves a point-in-time
        record. Restore one manually with
        auditpol /restore /file:<snapshot>\auditpol-backup.csv plus the
        values in its State.json.

    No setting in this kit requires a reboot. One conditional setting
    (AD CS AuditFilter, only when Certificate Services is installed) requires
    a CertSvc SERVICE RESTART - this script sets the value, warns, and never
    restarts anything itself.

    Requires: Windows PowerShell 5.1+, local Administrator. No modules.
    Works standalone or domain joined; DC-only items are skipped as
    NOT APPLICABLE on non-DCs.

.PARAMETER IncludeHighVolume
    Also apply HighVolume tier items (process creation + command line,
    PowerShell script block and module logging, Filtering Platform
    Connection, Sensitive Privilege Use, Crypto-DPAPI debug channel, IPsec
    Driver auditing).

.PARAMETER IncludeOptional
    Deprecated, ignored with a warning. The Optional tier was folded into
    HighVolume in v2 (ADR-002); use -IncludeHighVolume.

.PARAMETER BaselineFile
    Path to a selection CSV produced by New-LoggingBaseline.ps1 (columns
    ItemType, Id, Selected are read; the rest is human context). When given,
    tier switches are ignored and only Selected = Y items are applied.

.PARAMETER Rollback
    Restore audit policy, channel sizes/state and registry values captured
    at first run, then exit.

.PARAMETER BaselineDir
    Folder holding the first-run capture. Default: .\Baseline next to this script.

.EXAMPLE
    .\Enable-LoggingBaseline.ps1 -WhatIf
    Show the full diff of what would change, change nothing.

.EXAMPLE
    .\Enable-LoggingBaseline.ps1 -IncludeHighVolume
    Apply Core + HighVolume tiers.

.EXAMPLE
    .\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv -WhatIf
    Preview exactly what a custom baseline selection would change.

.EXAMPLE
    .\Enable-LoggingBaseline.ps1 -Rollback
    Put everything back the way it was before the first run.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    [string]$BaselineFile,
    [switch]$Rollback,
    # Defaults resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$BaselineDir,
    [string]$LogDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($BaselineDir)) { $BaselineDir = Join-Path $PSScriptRoot 'Baseline' }
if ([string]::IsNullOrEmpty($LogDir))      { $LogDir      = Join-Path $PSScriptRoot 'Logs' }

. (Join-Path $PSScriptRoot 'WinLogKit.Settings.ps1')
. (Join-Path $PSScriptRoot 'WinLogKit.Common.ps1')

# ---------------------------------------------------------------- helpers ---

# Host probes, registry reads and the selection model come from
# WinLogKit.Common.ps1. The registry writers live here because this is
# the one script that writes; they use the .NET API for the reason noted
# there (a required value is literally named '*').
function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Kind)
    $kindEnum = [Microsoft.Win32.RegistryValueKind]::$Kind
    [Microsoft.Win32.Registry]::SetValue((ConvertTo-NetRegPath $Path), $Name, $Value, $kindEnum)
}

function Remove-RegValue {
    param([string]$Path, [string]$Name)
    $subKey = (ConvertTo-NetRegPath $Path) -replace '^HKEY_LOCAL_MACHINE\\', ''
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($subKey, $true)
    if ($null -ne $key) {
        try { $key.DeleteValue($Name, $false) } finally { $key.Close() }
    }
}

function Set-SmbAuditSetting {
    param([hashtable]$Item)
    $setParams = @{ $Item.Id = $Item.Value; Force = $true }
    if ($Item.Side -eq 'Server') { Set-SmbServerConfiguration @setParams } else { Set-SmbClientConfiguration @setParams }
}

function Get-AdcsRegPath {
    # Resolve the active CA registry key, or $null when AD CS is not installed.
    $active = Get-RegValue -Path $script:BaselineAdcsAuditFilter.BasePath -Name 'Active'
    if ([string]::IsNullOrEmpty($active)) { return $null }
    return ($script:BaselineAdcsAuditFilter.BasePath + '\' + $active)
}

$results = New-Object System.Collections.Generic.List[object]
function Add-Result {
    param([string]$Area, [string]$Item, [string]$Action, [string]$Detail = '')
    $results.Add([pscustomobject]@{ Area = $Area; Item = $Item; Action = $Action; Detail = $Detail })
    $colour = switch ($Action) {
        'Changed'         { 'Green' }
        'WouldChange'     { 'Cyan' }
        'AlreadyCorrect'  { 'DarkGray' }
        'PendingDecision' { 'Yellow' }
        'Excluded'        { 'DarkGray' }
        'NotApplicable'   { 'DarkGray' }
        'Warning'         { 'Yellow' }
        'Error'           { 'Red' }
        default           { 'Gray' }
    }
    Write-Host ('[{0,-15}] {1,-9} {2}  {3}' -f $Action, $Area, $Item, $Detail) -ForegroundColor $colour
}

# One decision point for every item: baseline file wins when present,
# otherwise the tier switches decide (WinLogKit.Common.ps1 resolves both
# into $script:Selection). Returns Apply | PendingDecision | Excluded |
# NotListed.
$script:Selection = Resolve-BaselineSelection -BaselineFile $BaselineFile -IncludeHighVolume $IncludeHighVolume -IncludeOptional $IncludeOptional
function Get-ItemDecision {
    param([string]$Tier, [string]$ItemType, [string]$Id)
    if ($null -ne $script:Selection.Map) {
        $key = ("$ItemType|$Id").ToUpper()
        if (-not $script:Selection.Map.ContainsKey($key)) { return 'NotListed' }
        if ($script:Selection.Map[$key]) { return 'Apply' }
        return 'Excluded'
    }
    if (Test-ItemSelected $script:Selection $ItemType $Id $Tier) { return 'Apply' }
    return 'PendingDecision'
}

# ------------------------------------------------------------------ setup ---

if (-not (Test-IsAdmin)) {
    Write-Error 'This script must run as local Administrator (it reads and writes audit policy).'
    exit 1
}

# -WhatIf:$false: the transcript is the record of the run - a -WhatIf diff is
# exactly what you want written to disk, and without the override
# Start-Transcript is itself skipped under -WhatIf, leaving the finally-block
# Stop-Transcript to throw "host is not currently transcribing".
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force -WhatIf:$false | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$transcriptFile = Join-Path $LogDir "Enable-LoggingBaseline_$stamp.log"
Start-Transcript -Path $transcriptFile -WhatIf:$false | Out-Null

$exitCode = 0
try {
    $domainRole  = Get-DomainRole
    $baselineJson = Join-Path $BaselineDir 'LoggingBaseline-FirstRun.json'
    $auditBackup  = Join-Path $BaselineDir 'auditpol-backup.csv'

    Write-Host ''
    Write-Host "Host profile       : $(Get-OsType), $domainRole"
    if ($null -ne $script:Selection.Map) {
        Write-Host "Baseline file      : $BaselineFile ($(@($script:Selection.Map.Values | Where-Object { $_ }).Count) items selected; tier switches ignored)"
    } else {
        Write-Host "Tiers selected     : Core$(if ($IncludeHighVolume) {' + HighVolume'})"
    }
    Write-Host "Transcript         : $transcriptFile"
    Write-Host ''

    # ------------------------------------------------------------ rollback ---
    if ($Rollback) {
        if (-not (Test-Path $baselineJson)) {
            Write-Error "No baseline found at $baselineJson - nothing to roll back to."
            exit 1
        }
        $baseline = Get-Content $baselineJson -Raw | ConvertFrom-Json
        Write-Host "Rolling back to baseline captured $($baseline.CapturedUtc) UTC" -ForegroundColor Yellow

        if ((Test-Path $auditBackup) -and $PSCmdlet.ShouldProcess('Audit policy', "auditpol /restore from $auditBackup")) {
            auditpol /restore /file:"$auditBackup" | Out-Null
            Add-Result 'AuditPol' 'All subcategories' 'Changed' 'Restored from first-run backup'
        }

        foreach ($ch in $baseline.Channels) {
            try {
                $log = Get-WinEvent -ListLog $ch.Name -ErrorAction SilentlyContinue
                if ($null -eq $log) { Add-Result 'Channel' $ch.Name 'NotApplicable' 'Channel no longer present'; continue }
                if ($PSCmdlet.ShouldProcess($ch.Name, "Restore size=$($ch.MaximumSizeInBytes) enabled=$($ch.IsEnabled)")) {
                    $enabledText = 'false'; if ($ch.IsEnabled) { $enabledText = 'true' }
                    wevtutil sl "$($ch.Name)" /ms:$($ch.MaximumSizeInBytes) /e:$enabledText 2>&1 | Out-Null
                    Add-Result 'Channel' $ch.Name 'Changed' "Restored to $([math]::Round($ch.MaximumSizeInBytes/1MB)) MB, enabled=$($ch.IsEnabled)"
                }
            } catch { Add-Result 'Channel' $ch.Name 'Error' $_.Exception.Message; $exitCode = 1 }
        }

        if ($baseline.PSObject.Properties.Name -contains 'SmbAudit') {
            $smbNow = Get-SmbAuditState
            foreach ($sb in $baseline.SmbAudit) {
                try {
                    if (-not $smbNow.ContainsKey($sb.Id)) { continue }
                    if ($PSCmdlet.ShouldProcess("SMB audit: $($sb.Id)", "Restore to $($sb.Value)")) {
                        Set-SmbAuditSetting -Item @{ Id = $sb.Id; Side = $sb.Side; Value = [bool]$sb.Value }
                        Add-Result 'SmbAudit' $sb.Id 'Changed' "Restored to $($sb.Value)"
                    }
                } catch { Add-Result 'SmbAudit' $sb.Id 'Error' $_.Exception.Message; $exitCode = 1 }
            }
        }

        foreach ($rv in $baseline.Registry) {
            try {
                if ($rv.Existed) {
                    if ($PSCmdlet.ShouldProcess("$($rv.Path)\$($rv.Name)", "Restore value $($rv.Value)")) {
                        Set-RegValue -Path $rv.Path -Name $rv.Name -Value $rv.Value -Kind $rv.Kind
                        Add-Result 'Registry' "$($rv.Path)\$($rv.Name)" 'Changed' "Restored to $($rv.Value)"
                    }
                } else {
                    if ($PSCmdlet.ShouldProcess("$($rv.Path)\$($rv.Name)", 'Remove value (did not exist at baseline)')) {
                        Remove-RegValue -Path $rv.Path -Name $rv.Name
                        Add-Result 'Registry' "$($rv.Path)\$($rv.Name)" 'Changed' 'Removed (did not exist at baseline)'
                    }
                }
            } catch { Add-Result 'Registry' "$($rv.Path)\$($rv.Name)" 'Error' $_.Exception.Message; $exitCode = 1 }
        }

        Write-Host ''
        Write-Host 'Rollback complete. If AD CS AuditFilter was restored, restart CertSvc for it to take effect.' -ForegroundColor Yellow
        exit $exitCode
    }

    # ---------------------------------------------------- state snapshots ---
    # Save-StateSnapshot captures the complete pre-change state (full audit
    # policy backup, channel sizes/enablement, registry values including
    # absence, SMB audit settings) into a directory: the protected first-run
    # rollback baseline, and a timestamped snapshot before every later apply.
    # Get-CurrentKitState is its read-only core: channel, registry and SMB
    # audit state for every settings-table item (auditpol /backup covers
    # every audit subcategory on its own).
    function Get-CurrentKitState {
        $chState = @()
        foreach ($ch in $script:BaselineChannels) {
            $log = Get-WinEvent -ListLog $ch.Name -ErrorAction SilentlyContinue
            if ($null -ne $log) {
                $chState += @{ Name = $ch.Name; MaximumSizeInBytes = $log.MaximumSizeInBytes; IsEnabled = $log.IsEnabled }
            }
        }

        $regState = @()
        $regItems = @($script:BaselineRegistrySettings)
        $adcsPath = Get-AdcsRegPath
        if ($null -ne $adcsPath) {
            $regItems += @(@{ Path = $adcsPath; Name = $script:BaselineAdcsAuditFilter.Name; Kind = $script:BaselineAdcsAuditFilter.Kind })
        }
        foreach ($ri in $regItems) {
            $cur = Get-RegValue -Path $ri.Path -Name $ri.Name
            $regState += @{
                Path = $ri.Path; Name = $ri.Name; Kind = $ri.Kind
                Existed = ($null -ne $cur); Value = $cur
            }
        }

        $smbState = @()
        $smbNow = Get-SmbAuditState
        foreach ($sa in $script:BaselineSmbAuditSettings) {
            if ($smbNow.ContainsKey($sa.Id)) {
                $smbState += @{ Id = $sa.Id; Side = $sa.Side; Value = $smbNow[$sa.Id] }
            }
        }

        return @{ Channels = $chState; Registry = $regState; SmbAudit = $smbState }
    }

    function Save-StateSnapshot {
        param([string]$Dir, [string]$JsonName)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        $backupFile = Join-Path $Dir 'auditpol-backup.csv'
        auditpol /backup /file:"$backupFile" | Out-Null
        # A snapshot without a working audit backup is worse than no snapshot:
        # the JSON marker would make later runs (and -Rollback) trust it.
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path $backupFile)) {
            throw "auditpol /backup failed (exit $LASTEXITCODE) - snapshot aborted, nothing was changed."
        }
        $state = Get-CurrentKitState
        @{
            CapturedUtc = (Get-Date).ToUniversalTime().ToString('s')
            Host        = $env:COMPUTERNAME
            Channels    = $state.Channels
            Registry    = $state.Registry
            SmbAudit    = $state.SmbAudit
        } | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $Dir $JsonName) -Encoding UTF8
    }

    # The first-run baseline is captured once, so settings added by a later
    # kit version (the PowerShell 7 items, #44) were missing from it and
    # -Rollback left them behind. Before changing anything, record any item
    # the baseline doesn't know yet, in its current state: the kit has never
    # touched it, so its current state IS its pre-kit state. Returns how many
    # items were added.
    function Add-NewItemsToFirstRun {
        param([string]$Path)
        $first = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
        $now = Get-CurrentKitState
        $known = @{}
        foreach ($r in @($first.Registry)) { if ($null -ne $r) { $known[("R|$($r.Path)|$($r.Name)").ToUpper()] = $true } }
        if ($first.PSObject.Properties.Name -contains 'Channels') { foreach ($c in @($first.Channels)) { if ($null -ne $c) { $known[("C|$($c.Name)").ToUpper()] = $true } } }
        if ($first.PSObject.Properties.Name -contains 'SmbAudit') { foreach ($s in @($first.SmbAudit)) { if ($null -ne $s) { $known[("S|$($s.Id)").ToUpper()] = $true } } }
        $addedUtc = (Get-Date).ToUniversalTime().ToString('s')
        $newReg = @($now.Registry | Where-Object { -not $known.ContainsKey(("R|$($_.Path)|$($_.Name)").ToUpper()) } | ForEach-Object { $_.AddedUtc = $addedUtc; $_ })
        $newCh  = @($now.Channels | Where-Object { -not $known.ContainsKey(("C|$($_.Name)").ToUpper()) } | ForEach-Object { $_.AddedUtc = $addedUtc; $_ })
        $newSmb = @($now.SmbAudit | Where-Object { -not $known.ContainsKey(("S|$($_.Id)").ToUpper()) } | ForEach-Object { $_.AddedUtc = $addedUtc; $_ })
        $count = $newReg.Count + $newCh.Count + $newSmb.Count
        if ($count -eq 0) { return 0 }
        $smbOld = @(); if ($first.PSObject.Properties.Name -contains 'SmbAudit') { $smbOld = @($first.SmbAudit | Where-Object { $null -ne $_ }) }
        $chOld  = @(); if ($first.PSObject.Properties.Name -contains 'Channels') { $chOld = @($first.Channels | Where-Object { $null -ne $_ }) }
        $json = @{
            CapturedUtc = $first.CapturedUtc
            Host        = $first.Host
            Channels    = @($chOld + $newCh)
            Registry    = @(@($first.Registry | Where-Object { $null -ne $_ }) + $newReg)
            SmbAudit    = @($smbOld + $newSmb)
        } | ConvertTo-Json -Depth 5
        # Never leave -Rollback without a readable baseline: write a temp copy
        # beside it, check it parses, then swap it in atomically, keeping the
        # previous version as .bak. A failure leaves the original untouched.
        # Full paths: File.Replace resolves relative ones against the process
        # directory, not the PowerShell location.
        $full = (Resolve-Path -LiteralPath $Path).Path
        $tmpPath = "$full.tmp"
        try {
            Set-Content -LiteralPath $tmpPath -Value $json -Encoding UTF8
            $null = Get-Content -LiteralPath $tmpPath -Raw | ConvertFrom-Json
            [System.IO.File]::Replace($tmpPath, $full, "$full.bak")
        } finally {
            if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force }
        }
        return $count
    }

    if (-not (Test-Path $baselineJson)) {
        # First real run: the protected rollback baseline, captured before
        # anything changes. -Rollback always restores THIS state.
        if ($WhatIfPreference) {
            Write-Host '[WhatIf] Baseline would be captured on the first real run (audit policy backup, channel sizes, registry values).' -ForegroundColor Cyan
        } else {
            Save-StateSnapshot -Dir $BaselineDir -JsonName 'LoggingBaseline-FirstRun.json'
            Write-Host "Baseline captured to $BaselineDir (audit policy backup + channel sizes + registry values)." -ForegroundColor Green
            Write-Host ''
        }
    } else {
        # Later applies: keep the first-run baseline untouched, but also
        # snapshot the CURRENT state so every apply has a point-in-time
        # record (e.g. before stepping up from Minimal to Heavy). Manual
        # point-in-time restore: auditpol /restore /file:<snapshot>\auditpol-backup.csv
        # plus the values recorded in its State.json.
        if ($WhatIfPreference) {
            Write-Host "Existing first-run baseline kept for -Rollback ($baselineJson). [WhatIf] A pre-change snapshot would be taken on a real run." -ForegroundColor DarkGray
        } else {
            $snapDir = Join-Path (Join-Path $BaselineDir 'snapshots') $stamp
            Save-StateSnapshot -Dir $snapDir -JsonName 'State.json'
            Write-Host "Existing first-run baseline kept for -Rollback. Pre-change snapshot of the current state saved to $snapDir." -ForegroundColor DarkGray
            $added = Add-NewItemsToFirstRun -Path $baselineJson
            if ($added -gt 0) { Write-Host "Added $added setting(s) new in this kit version to the rollback baseline, in their current (pre-kit) state." -ForegroundColor DarkGray }
        }
        Write-Host ''
    }

    # ------------------------------------------------------------- storage ---
    # Before any size is raised (and under -WhatIf): will the selected logs
    # fit on their drive once full? Warns only.
    $storageLogs = @()
    foreach ($ch in $script:BaselineChannels) {
        if ((Get-ItemDecision $ch.Tier 'Channel' $ch.Name) -ne 'Apply') { continue }
        $log = Get-WinEvent -ListLog $ch.Name -ErrorAction SilentlyContinue
        if ($null -eq $log) { continue }
        $storageLogs += [pscustomobject]@{ LogFilePath = $log.LogFilePath; FileSize = $log.FileSize; MaximumSizeInBytes = $log.MaximumSizeInBytes; TargetBytes = $ch.TargetBytes }
    }
    Write-Host '=== Log storage (selected channels at their maximum size) ===' -ForegroundColor White
    Write-LogStorageCheck (@(Get-LogStorageCheck -Logs $storageLogs))
    Write-Host ''

    # ------------------------------------------------------------ channels ---
    Write-Host '=== Event log channels (size and enablement) ===' -ForegroundColor White
    foreach ($ch in $script:BaselineChannels) {
        $decision = Get-ItemDecision $ch.Tier 'Channel' $ch.Name
        if ($decision -eq 'PendingDecision') {
            Add-Result 'Channel' $ch.Name 'PendingDecision' "$($ch.Tier) tier - rerun with -Include$($ch.Tier) to apply"
            continue
        }
        if ($decision -eq 'Excluded')  { Add-Result 'Channel' $ch.Name 'Excluded' 'Selected = N in baseline file'; continue }
        if ($decision -eq 'NotListed') { Add-Result 'Channel' $ch.Name 'Excluded' 'Not listed in baseline file'; continue }
        $log = Get-WinEvent -ListLog $ch.Name -ErrorAction SilentlyContinue
        if ($null -eq $log) {
            $note = 'Channel not registered on this host'
            if ($ch.ContainsKey('MayBeAbsent') -and $ch.MayBeAbsent) { $note += ' (expected when the owning feature is not installed)' }
            Add-Result 'Channel' $ch.Name 'NotApplicable' $note
            continue
        }

        $needSize   = ($log.MaximumSizeInBytes -lt $ch.TargetBytes)   # only ever raise, never shrink
        $needEnable = ($ch.MustEnable -and -not $log.IsEnabled)

        if (-not $needSize -and -not $needEnable) {
            Add-Result 'Channel' $ch.Name 'AlreadyCorrect' "$([math]::Round($log.MaximumSizeInBytes/1MB)) MB, enabled=$($log.IsEnabled)"
            continue
        }

        $desc = @()
        if ($needSize)   { $desc += "size $([math]::Round($log.MaximumSizeInBytes/1MB)) MB -> $([math]::Round($ch.TargetBytes/1MB)) MB" }
        if ($needEnable) { $desc += 'enable (currently disabled)' }
        $descText = $desc -join ', '

        if ($PSCmdlet.ShouldProcess($ch.Name, $descText)) {
            try {
                if ($needSize)   { wevtutil sl "$($ch.Name)" /ms:$($ch.TargetBytes) 2>&1 | Out-Null }
                if ($needEnable) { wevtutil sl "$($ch.Name)" /e:true 2>&1 | Out-Null }
                Add-Result 'Channel' $ch.Name 'Changed' $descText
            } catch { Add-Result 'Channel' $ch.Name 'Error' $_.Exception.Message; $exitCode = 1 }
        } else {
            Add-Result 'Channel' $ch.Name 'WouldChange' $descText
        }
    }

    # ------------------------------------------------- audit subcategories ---
    Write-Host ''
    Write-Host '=== Advanced audit policy subcategories ===' -ForegroundColor White
    $currentAudit = Get-AuditPolicyByGuid
    foreach ($sub in $script:BaselineAuditSubcategories) {
        if ($sub.Scope -eq 'DomainController' -and $domainRole -ne 'DomainController') {
            Add-Result 'AuditPol' $sub.Name 'NotApplicable' 'Domain controller only - host is not a DC'
            continue
        }
        $decision = Get-ItemDecision $sub.Tier 'AuditPolicy' $sub.Guid
        if ($decision -eq 'PendingDecision') {
            Add-Result 'AuditPol' $sub.Name 'PendingDecision' "$($sub.Tier) tier - rerun with -Include$($sub.Tier) to apply"
            continue
        }
        if ($decision -eq 'Excluded')  { Add-Result 'AuditPol' $sub.Name 'Excluded' 'Selected = N in baseline file'; continue }
        if ($decision -eq 'NotListed') { Add-Result 'AuditPol' $sub.Name 'Excluded' 'Not listed in baseline file'; continue }

        # Compared as setting values (0..3), not localised text (#45).
        $desiredValue = Get-AuditSettingValue -Success $sub.Success -Failure $sub.Failure
        $desired      = Format-AuditSetting $desiredValue
        $guid         = $sub.Guid.ToUpper()
        $currentValue = $null
        if ($currentAudit.ContainsKey($guid)) { $currentValue = $currentAudit[$guid] }
        $current = Format-AuditSetting $currentValue

        if ($currentValue -eq $desiredValue) {
            Add-Result 'AuditPol' $sub.Name 'AlreadyCorrect' $desired
            continue
        }

        $descText = "'$current' -> '$desired'"
        if ($PSCmdlet.ShouldProcess("Audit subcategory: $($sub.Name)", $descText)) {
            $s = 'disable'; if ($sub.Success) { $s = 'enable' }
            $f = 'disable'; if ($sub.Failure) { $f = 'enable' }
            auditpol /set /subcategory:"{$($sub.Guid)}" /success:$s /failure:$f | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Add-Result 'AuditPol' $sub.Name 'Changed' $descText
            } else {
                Add-Result 'AuditPol' $sub.Name 'Error' "auditpol exit code $LASTEXITCODE"
                $exitCode = 1
            }
        } else {
            Add-Result 'AuditPol' $sub.Name 'WouldChange' $descText
        }
    }

    # ---------------------------------------------------- registry settings ---
    Write-Host ''
    Write-Host '=== Registry settings ===' -ForegroundColor White
    foreach ($rs in $script:BaselineRegistrySettings) {
        $itemLabel = "$($rs.Path)\$($rs.Name)"
        if ($rs.Scope -eq 'DomainController' -and $domainRole -ne 'DomainController') {
            Add-Result 'Registry' $itemLabel 'NotApplicable' 'Domain controller only - host is not a DC'
            continue
        }
        $decision = Get-ItemDecision $rs.Tier 'Registry' $rs.Id
        if ($decision -eq 'PendingDecision') {
            Add-Result 'Registry' $itemLabel 'PendingDecision' "$($rs.Tier) tier - rerun with -Include$($rs.Tier) to apply"
            continue
        }
        if ($decision -eq 'Excluded')  { Add-Result 'Registry' $itemLabel 'Excluded' 'Selected = N in baseline file'; continue }
        if ($decision -eq 'NotListed') { Add-Result 'Registry' $itemLabel 'Excluded' 'Not listed in baseline file'; continue }

        $current = Get-RegValue -Path $rs.Path -Name $rs.Name
        if ("$current" -eq "$($rs.Value)") {
            Add-Result 'Registry' $itemLabel 'AlreadyCorrect' "= $($rs.Value)"
            continue
        }

        $curText = '<absent>'; if ($null -ne $current) { $curText = "$current" }
        $descText = "$curText -> $($rs.Value)"
        if ($PSCmdlet.ShouldProcess($itemLabel, "Set to $($rs.Value) ($($rs.Kind))")) {
            try {
                Set-RegValue -Path $rs.Path -Name $rs.Name -Value $rs.Value -Kind $rs.Kind
                Add-Result 'Registry' $itemLabel 'Changed' $descText
            } catch { Add-Result 'Registry' $itemLabel 'Error' $_.Exception.Message; $exitCode = 1 }
        } else {
            Add-Result 'Registry' $itemLabel 'WouldChange' $descText
        }
    }

    # --------------------- SMB signing/encryption auditing (Server 2025+) ---
    Write-Host ''
    Write-Host '=== SMB signing/encryption auditing (Windows Server 2025+) ===' -ForegroundColor White
    $smbState = Get-SmbAuditState
    foreach ($sa in $script:BaselineSmbAuditSettings) {
        $decision = Get-ItemDecision $sa.Tier 'SmbAudit' $sa.Id
        if ($decision -eq 'PendingDecision') {
            Add-Result 'SmbAudit' $sa.Id 'PendingDecision' "$($sa.Tier) tier - rerun with -Include$($sa.Tier) to apply"
            continue
        }
        if ($decision -eq 'Excluded')  { Add-Result 'SmbAudit' $sa.Id 'Excluded' 'Selected = N in baseline file'; continue }
        if ($decision -eq 'NotListed') { Add-Result 'SmbAudit' $sa.Id 'Excluded' 'Not listed in baseline file'; continue }
        if (-not $smbState.ContainsKey($sa.Id)) {
            Add-Result 'SmbAudit' $sa.Id 'NotApplicable' 'Requires Windows Server 2025 / Windows 11 24H2 or later'
            continue
        }
        if ($smbState[$sa.Id] -eq $sa.Value) {
            Add-Result 'SmbAudit' $sa.Id 'AlreadyCorrect' "= $($sa.Value)"
            continue
        }
        if ($PSCmdlet.ShouldProcess("SMB audit ($($sa.Side)): $($sa.Id)", "Set to $($sa.Value)")) {
            try {
                Set-SmbAuditSetting -Item $sa
                Add-Result 'SmbAudit' $sa.Id 'Changed' "$($smbState[$sa.Id]) -> $($sa.Value)"
            } catch { Add-Result 'SmbAudit' $sa.Id 'Error' $_.Exception.Message; $exitCode = 1 }
        } else {
            Add-Result 'SmbAudit' $sa.Id 'WouldChange' "$($smbState[$sa.Id]) -> $($sa.Value)"
        }
    }

    # -------------------------------------- AD CS AuditFilter (conditional) ---
    Write-Host ''
    Write-Host '=== AD CS audit filter (conditional) ===' -ForegroundColor White
    $adcsPath = Get-AdcsRegPath
    $adcsDecision = Get-ItemDecision $script:BaselineAdcsAuditFilter.Tier 'Registry' $script:BaselineAdcsAuditFilter.Id
    if ($adcsDecision -eq 'Excluded' -or $adcsDecision -eq 'NotListed') {
        Add-Result 'Registry' 'AD CS AuditFilter' 'Excluded' 'Deselected in baseline file'
    } elseif ($null -eq $adcsPath) {
        Add-Result 'Registry' 'AD CS AuditFilter' 'NotApplicable' 'Certificate Services not installed on this host'
    } else {
        $af = $script:BaselineAdcsAuditFilter
        $current = Get-RegValue -Path $adcsPath -Name $af.Name
        if ("$current" -eq "$($af.Value)") {
            Add-Result 'Registry' "$adcsPath\$($af.Name)" 'AlreadyCorrect' "= $($af.Value)"
        } else {
            $curText = '<absent>'; if ($null -ne $current) { $curText = "$current" }
            if ($PSCmdlet.ShouldProcess("$adcsPath\$($af.Name)", "Set to $($af.Value) - CertSvc restart will be required")) {
                try {
                    Set-RegValue -Path $adcsPath -Name $af.Name -Value $af.Value -Kind $af.Kind
                    Add-Result 'Registry' "$adcsPath\$($af.Name)" 'Changed' "$curText -> $($af.Value)"
                    Add-Result 'Registry' 'AD CS AuditFilter' 'Warning' 'SERVICE RESTART REQUIRED: restart CertSvc in an approved change window (Restart-Service CertSvc). This script never restarts services itself.'
                } catch { Add-Result 'Registry' "$adcsPath\$($af.Name)" 'Error' $_.Exception.Message; $exitCode = 1 }
            } else {
                Add-Result 'Registry' "$adcsPath\$($af.Name)" 'WouldChange' "$curText -> $($af.Value) (then CertSvc restart required)"
            }
        }
    }

    # ------------------------------------------------------------- summary ---
    Write-Host ''
    Write-Host '=== Summary ===' -ForegroundColor White
    $results | Group-Object Action | Sort-Object Name | ForEach-Object {
        Write-Host ('  {0,-15} {1}' -f $_.Name, $_.Count)
    }

    $pending = @($results | Where-Object { $_.Action -eq 'PendingDecision' })
    if ($pending.Count -gt 0) {
        Write-Host ''
        Write-Host 'PENDING DECISION - high volume settings NOT applied (deliberate; a human decides):' -ForegroundColor Yellow
        $pending | ForEach-Object { Write-Host "  - $($_.Item)  [$($_.Detail)]" -ForegroundColor Yellow }
        Write-Host '  Review the volume impact section in README.md, then rerun with -IncludeHighVolume.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host 'Reboot status: NO reboot is required by any setting in this kit.' -ForegroundColor Green
    if (@($results | Where-Object { $_.Action -eq 'Warning' }).Count -gt 0) {
        Write-Host 'One or more warnings above need action (see SERVICE RESTART REQUIRED).' -ForegroundColor Yellow
    }
    Write-Host "Transcript saved to $transcriptFile"
}
finally {
    # Tolerate a transcript that never started (e.g. transcription disabled by
    # policy) rather than masking the real result with a Stop-Transcript error.
    try { Stop-Transcript | Out-Null } catch { Write-Verbose "Stop-Transcript: $($_.Exception.Message)" }
}
exit $exitCode
