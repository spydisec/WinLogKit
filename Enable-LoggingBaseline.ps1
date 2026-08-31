<#
.SYNOPSIS
    Enables the Windows Server logging baseline (event log channels,
    advanced audit policy subcategories and registry settings) derived from
    the Yamato Security EnableWindowsLogSettings / WELA baselines.

.DESCRIPTION
    Idempotent - safe to run repeatedly. Every item is compared to its target
    first; already-correct items are reported and left alone.

    Tiers:
      Core        applied by default.
      HighVolume  material event volume / performance impact. NOT applied
                  unless -IncludeHighVolume is given - listed as PENDING
                  DECISION so a human chooses.
      Optional    situational (PowerShell transcription, DPAPI debug channel).
                  Applied only with -IncludeOptional.

    On the FIRST real (non -WhatIf) run, the current audit policy, channel
    sizes and registry values are captured to a baseline folder. -Rollback
    restores that captured state.

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
    Connection, Sensitive Privilege Use).

.PARAMETER IncludeOptional
    Also apply Optional tier items (PowerShell transcription, Crypto-DPAPI
    debug channel).

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
    .\Enable-LoggingBaseline.ps1 -Rollback
    Put everything back the way it was before the first run.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    [switch]$Rollback,
    [string]$BaselineDir = (Join-Path $PSScriptRoot 'Baseline'),
    [string]$LogDir      = (Join-Path $PSScriptRoot 'Logs')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')

# ---------------------------------------------------------------- helpers ---

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DomainRole {
    # Win32_ComputerSystem.DomainRole: 0/1 standalone, 2/3 member, 4/5 domain controller
    $role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
    if ($role -ge 4) { return 'DomainController' }
    if ($role -ge 2) { return 'Member' }
    return 'Standalone'
}

# Registry access uses the .NET API throughout, not *-ItemProperty, because
# one required value is literally named '*' and the ItemProperty cmdlets
# treat that as a wildcard.
function ConvertTo-NetRegPath { param([string]$Path) $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' }

function Get-RegValue {
    param([string]$Path, [string]$Name)
    [Microsoft.Win32.Registry]::GetValue((ConvertTo-NetRegPath $Path), $Name, $null)
}

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

function Get-AuditPolicyByGuid {
    # One auditpol call for everything; returns hashtable GUID -> inclusion setting text.
    $map = @{}
    $csv = auditpol /get /category:* /r | Where-Object { $_ -match '\S' } | ConvertFrom-Csv
    foreach ($row in $csv) {
        $guid = ($row.'Subcategory GUID' -replace '[{}]', '').ToUpper()
        $map[$guid] = $row.'Inclusion Setting'
    }
    return $map
}

function Get-DesiredInclusion {
    param([bool]$Success, [bool]$Failure)
    if ($Success -and $Failure) { return 'Success and Failure' }
    if ($Success) { return 'Success' }
    if ($Failure) { return 'Failure' }
    return 'No Auditing'
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
        'NotApplicable'   { 'DarkGray' }
        'Warning'         { 'Yellow' }
        'Error'           { 'Red' }
        default           { 'Gray' }
    }
    Write-Host ('[{0,-15}] {1,-9} {2}  {3}' -f $Action, $Area, $Item, $Detail) -ForegroundColor $colour
}

function Test-TierSelected {
    param([string]$Tier)
    if ($Tier -eq 'Core') { return $true }
    if ($Tier -eq 'HighVolume') { return [bool]$IncludeHighVolume }
    if ($Tier -eq 'Optional') { return [bool]$IncludeOptional }
    return $false
}

# ------------------------------------------------------------------ setup ---

if (-not (Test-IsAdmin)) {
    Write-Error 'This script must run as local Administrator (it reads and writes audit policy).'
    exit 1
}

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$transcriptFile = Join-Path $LogDir "Enable-LoggingBaseline_$stamp.log"
Start-Transcript -Path $transcriptFile | Out-Null

$exitCode = 0
try {
    $domainRole  = Get-DomainRole
    $baselineJson = Join-Path $BaselineDir 'LoggingBaseline-FirstRun.json'
    $auditBackup  = Join-Path $BaselineDir 'auditpol-backup.csv'

    Write-Host ''
    Write-Host "Host role          : $domainRole"
    Write-Host "Tiers selected     : Core$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
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

    # ---------------------------------------------------- baseline capture ---
    # Captured once, on the first real run, before anything is changed.
    if (-not (Test-Path $baselineJson)) {
        if ($WhatIfPreference) {
            Write-Host '[WhatIf] Baseline would be captured on the first real run (audit policy backup, channel sizes, registry values).' -ForegroundColor Cyan
        } else {
            New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null
            auditpol /backup /file:"$auditBackup" | Out-Null

            $chBaseline = @()
            foreach ($ch in $script:BaselineChannels) {
                $log = Get-WinEvent -ListLog $ch.Name -ErrorAction SilentlyContinue
                if ($null -ne $log) {
                    $chBaseline += @{ Name = $ch.Name; MaximumSizeInBytes = $log.MaximumSizeInBytes; IsEnabled = $log.IsEnabled }
                }
            }

            $regBaseline = @()
            $regItems = @($script:BaselineRegistrySettings)
            $adcsPath = Get-AdcsRegPath
            if ($null -ne $adcsPath) {
                $regItems += @(@{ Path = $adcsPath; Name = $script:BaselineAdcsAuditFilter.Name; Kind = $script:BaselineAdcsAuditFilter.Kind })
            }
            foreach ($ri in $regItems) {
                $cur = Get-RegValue -Path $ri.Path -Name $ri.Name
                $regBaseline += @{
                    Path = $ri.Path; Name = $ri.Name; Kind = $ri.Kind
                    Existed = ($null -ne $cur); Value = $cur
                }
            }

            @{
                CapturedUtc = (Get-Date).ToUniversalTime().ToString('s')
                Host        = $env:COMPUTERNAME
                Channels    = $chBaseline
                Registry    = $regBaseline
            } | ConvertTo-Json -Depth 5 | Set-Content -Path $baselineJson -Encoding UTF8

            Write-Host "Baseline captured to $BaselineDir (audit policy backup + channel sizes + registry values)." -ForegroundColor Green
            Write-Host ''
        }
    } else {
        Write-Host "Existing baseline found ($baselineJson) - keeping the original first-run capture for rollback." -ForegroundColor DarkGray
        Write-Host ''
    }

    # ------------------------------------------------------------ channels ---
    Write-Host '=== Event log channels (size and enablement) ===' -ForegroundColor White
    foreach ($ch in $script:BaselineChannels) {
        if (-not (Test-TierSelected $ch.Tier)) {
            Add-Result 'Channel' $ch.Name 'PendingDecision' "$($ch.Tier) tier - rerun with -Include$($ch.Tier) to apply"
            continue
        }
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
        if (-not (Test-TierSelected $sub.Tier)) {
            Add-Result 'AuditPol' $sub.Name 'PendingDecision' "$($sub.Tier) tier - rerun with -Include$($sub.Tier) to apply"
            continue
        }

        $desired = Get-DesiredInclusion -Success $sub.Success -Failure $sub.Failure
        $guid    = $sub.Guid.ToUpper()
        $current = 'Unknown'
        if ($currentAudit.ContainsKey($guid)) { $current = $currentAudit[$guid] }

        if ($current -eq $desired) {
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
        if (-not (Test-TierSelected $rs.Tier)) {
            Add-Result 'Registry' $itemLabel 'PendingDecision' "$($rs.Tier) tier - rerun with -Include$($rs.Tier) to apply"
            continue
        }

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

    # -------------------------------------- AD CS AuditFilter (conditional) ---
    Write-Host ''
    Write-Host '=== AD CS audit filter (conditional) ===' -ForegroundColor White
    $adcsPath = Get-AdcsRegPath
    if ($null -eq $adcsPath) {
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
        Write-Host 'PENDING DECISION - high volume / optional settings NOT applied (deliberate; a human decides):' -ForegroundColor Yellow
        $pending | ForEach-Object { Write-Host "  - $($_.Item)  [$($_.Detail)]" -ForegroundColor Yellow }
        Write-Host '  Review the volume impact section in README.md, then rerun with -IncludeHighVolume and/or -IncludeOptional.' -ForegroundColor Yellow
    }

    Write-Host ''
    Write-Host 'Reboot status: NO reboot is required by any setting in this kit.' -ForegroundColor Green
    if (@($results | Where-Object { $_.Action -eq 'Warning' }).Count -gt 0) {
        Write-Host 'One or more warnings above need action (see SERVICE RESTART REQUIRED).' -ForegroundColor Yellow
    }
    Write-Host "Transcript saved to $transcriptFile"
}
finally {
    Stop-Transcript | Out-Null
}
exit $exitCode
