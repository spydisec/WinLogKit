# =============================================================================
# WinLogKit.Common.ps1
# Shared helpers, dot-sourced by the kit scripts right after the settings
# table. Everything here is read-only against the host: host probes, registry
# reads, the audit policy and SMB audit-state readers and the one selection model (tier switches
# or a selection CSV) that Enable, Test, the coverage report and the fleet
# generators all use. Registry writers stay in Enable-LoggingBaseline.ps1,
# the only script that writes.
#
# The Intune pack generator embeds its own copies of what the generated
# scripts need: those must stay self-contained.
#
# PowerShell 5.1 compatible. No external module dependencies.
# =============================================================================

Set-StrictMode -Version 2.0

# ------------------------------------------------------------ host probes ---

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

# Is PowerShell 7 (pwsh.exe) on this host? True when this script is itself
# running in PowerShell 7; otherwise MSI installs register under
# PowerShellCore\InstalledVersions, zip installs usually sit in Program
# Files, and Store installs put pwsh.exe on the PATH. A portable copy
# unpacked anywhere else, and not running this script, can't be found.
function Test-PowerShell7Installed {
    if ($PSVersionTable.PSEdition -eq 'Core' -and $PSVersionTable.PSVersion.Major -ge 7) { return $true }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions') { return $true }
    if ($env:ProgramFiles -and (Test-Path (Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'))) { return $true }
    return ($null -ne (Get-Command pwsh.exe -CommandType Application -ErrorAction SilentlyContinue))
}

function Get-OsType {
    # Win32_OperatingSystem.ProductType: 1 workstation, 2 domain controller, 3 server
    $pt = (Get-CimInstance -ClassName Win32_OperatingSystem).ProductType
    if ($pt -eq 1) { return 'Workstation' }
    if ($pt -eq 2) { return 'Domain Controller' }
    return 'Server'
}

# ---------------------------------------------------------- registry read ---

# Registry access uses the .NET API throughout, not *-ItemProperty, because
# one required value is literally named '*' and the ItemProperty cmdlets
# treat that as a wildcard.
function ConvertTo-NetRegPath { param([string]$Path) $Path -replace '^HKLM:\\', 'HKEY_LOCAL_MACHINE\' }

function Get-RegValue {
    param([string]$Path, [string]$Name)
    [Microsoft.Win32.Registry]::GetValue((ConvertTo-NetRegPath $Path), $Name, $null)
}

# ----------------------------------------------------------- audit policy ---

# Audit policy is read as numbers, not words (#45). auditpol /get /r prints
# each setting as text that is translated on non-English Windows ("Success
# and Failure" only in English), so matching on it failed correct hosts.
# auditpol /backup writes the same data with a numeric Setting Value
# (0 none, 1 Success, 2 Failure, 3 both) keyed by subcategory GUID - the
# format Group Policy uses. Columns are read by position (4th = GUID,
# 7th = value) in case the header row is translated too.

# Parses auditpol /backup output into subcategory GUID -> setting value.
# Rows without a GUID (audit options, global SACLs) are skipped. The export
# can also hold per-user audit rows, so the system-wide rows (Policy Target
# 'System') win; if none carry that word (a translated export), the first row
# per subcategory is used rather than reading nothing.
function ConvertFrom-AuditPolicyBackup {
    param([string[]]$Lines)
    $rows = @(@($Lines | Select-Object -Skip 1 | Where-Object { $_ -match '\S' }) |
        ConvertFrom-Csv -Header 'Machine', 'Target', 'Subcategory', 'Guid', 'Inclusion', 'Exclusion', 'Value' |
        Where-Object { $null -ne $_ })
    $valid = @($rows | Where-Object {
        ("$($_.Guid)" -replace '[{}]', '').Trim() -match '^[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$' -and "$($_.Value)".Trim() -match '^[0-3]$' })
    $system = @($valid | Where-Object { "$($_.Target)".Trim() -eq 'System' })
    if ($system.Count -gt 0) { $valid = $system }
    $map = @{}
    foreach ($row in $valid) {
        $guid = ("$($row.Guid)" -replace '[{}]', '').Trim().ToUpper()
        if (-not $map.ContainsKey($guid)) { $map[$guid] = [int]"$($row.Value)".Trim() }
    }
    return $map
}

# Live audit policy: subcategory GUID -> setting value 0..3. Needs admin.
function Get-AuditPolicyByGuid {
    $file = Join-Path ([IO.Path]::GetTempPath()) ('winlogkit-auditpol-{0}.csv' -f [guid]::NewGuid())
    try {
        $out = auditpol /backup /file:"$file"
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $file)) {
            throw "auditpol /backup failed with exit code $LASTEXITCODE (run elevated): $(($out | Select-Object -First 2) -join ' ')"
        }
        return (ConvertFrom-AuditPolicyBackup -Lines (Get-Content -LiteralPath $file))
    } finally {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
}

# Success/Failure flags -> setting value, and back to English for output.
function Get-AuditSettingValue {
    param([bool]$Success, [bool]$Failure)
    return ([int]$Success + 2 * [int]$Failure)
}

function Format-AuditSetting {
    param($Value)
    switch ("$Value") {
        '0' { return 'No Auditing' }
        '1' { return 'Success' }
        '2' { return 'Failure' }
        '3' { return 'Success and Failure' }
    }
    return 'Unknown'
}

# ------------------------------------------------------------ SMB auditing ---

# Current state of the Server 2025+ SMB signing/encryption audit settings.
# Returns a hashtable Id -> current bool; items missing from the hashtable are
# unsupported on this OS (the properties only exist on Server 2025 / Win11 24H2+).
function Get-SmbAuditState {
    $state = @{}
    $srv = $null; $cli = $null
    try { $srv = Get-SmbServerConfiguration -ErrorAction Stop } catch { $srv = $null }
    try { $cli = Get-SmbClientConfiguration -ErrorAction Stop } catch { $cli = $null }
    foreach ($item in $script:BaselineSmbAuditSettings) {
        $cfg = $srv
        if ($item.Side -eq 'Client') { $cfg = $cli }
        if ($null -ne $cfg -and ($cfg.PSObject.Properties.Name -contains $item.Id)) {
            $state[$item.Id] = [bool]$cfg.($item.Id)
        }
    }
    return $state
}

# -------------------------------------------------------------- selection ---
#
# A selection answers "is this item on?" for every item in the settings
# table. It comes from one of two places, and a baseline CSV always wins:
#   - a selection CSV from New-LoggingBaseline.ps1 (or a preset): listed rows
#     decide, unlisted items are off
#   - the tier switches: Core is always on, HighVolume only with
#     -IncludeHighVolume. (v2 folded the Optional tier into HighVolume, ADR-002;
#     -IncludeOptional is still accepted for one release and only warns.)

# Every "ITEMTYPE|ID" key the settings table defines, as a hashtable set.
function Get-BaselineItemKeySet {
    $keys = @{}
    foreach ($ch in $script:BaselineChannels)          { $keys[("Channel|$($ch.Name)").ToUpper()] = $true }
    foreach ($sub in $script:BaselineAuditSubcategories) { $keys[("AuditPolicy|$($sub.Guid)").ToUpper()] = $true }
    foreach ($rs in $script:BaselineRegistrySettings)   { $keys[("Registry|$($rs.Id)").ToUpper()] = $true }
    foreach ($sa in $script:BaselineSmbAuditSettings)   { $keys[("SmbAudit|$($sa.Id)").ToUpper()] = $true }
    $keys[("Registry|$($script:BaselineAdcsAuditFilter.Id)").ToUpper()] = $true
    return $keys
}

# Selection map from a selection CSV: "ITEMTYPE|ID" -> bool. The file is
# checked first: the wrong CSV (a Results export, say) must stop the run,
# not quietly select nothing. A CSV whose rows match nothing in the settings
# table is rejected for the same reason; rows for items this kit version
# does not know (an older CSV, a renamed setting) are warned about and
# ignored, since unlisted items are excluded anyway.
function Import-BaselineSelection {
    param([string]$Path)
    $rows = @(Import-Csv $Path)
    if ($rows.Count -eq 0) {
        Write-Error "Baseline file has no rows: $Path"
        exit 1
    }
    $columns = @($rows[0].PSObject.Properties.Name)
    $missing = @('ItemType', 'Id', 'Selected' | Where-Object { $columns -notcontains $_ })
    if ($missing.Count -gt 0) {
        Write-Error "Not a selection CSV (missing column(s): $($missing -join ', ')): $Path (build one with New-LoggingBaseline.ps1 or use a preset)"
        exit 1
    }
    $map = @{}
    $n = 0
    foreach ($row in $rows) {
        $n++
        if ([string]::IsNullOrWhiteSpace($row.ItemType) -or [string]::IsNullOrWhiteSpace($row.Id)) {
            Write-Error "Baseline file row $n has an empty ItemType or Id: $Path"
            exit 1
        }
        $key = ("$($row.ItemType)|$($row.Id)").ToUpper()
        if ($map.ContainsKey($key)) {
            Write-Error "Baseline file lists $($row.ItemType) '$($row.Id)' more than once (row $n): $Path"
            exit 1
        }
        $map[$key] = ("$($row.Selected)".Trim() -match '^(Y|YES|TRUE|1)$')
    }
    $known = Get-BaselineItemKeySet
    $unknown = @($map.Keys | Where-Object { -not $known.ContainsKey($_) } | Sort-Object)
    if ($unknown.Count -eq $map.Count) {
        Write-Error "No row in the baseline file matches a setting in this kit (first: $($unknown[0])): $Path (build one with New-LoggingBaseline.ps1 or use a preset)"
        exit 1
    }
    foreach ($u in $unknown) { Write-Warning "Baseline file lists an item this kit does not know, ignored: $u" }
    return $map
}

# Is this settings item part of a reference baseline definition (one entry
# of tools\reference-baselines.psd1)? Used by the preset and Reference page
# generators, so both read membership the same way.
function Test-ReferenceBaselineItem {
    param([hashtable]$Definition, [string]$ItemType, [string]$Id)
    switch ($ItemType) {
        'AuditPolicy' { foreach ($prefix in $Definition.AuditPrefixes) { if ($Id.ToUpper().StartsWith($prefix)) { return $true } }; return $false }
        'Registry'    { return ($Definition.RegistryIds -contains $Id) }
        'Channel'     { return ($Definition.Channels -contains $Id) }
    }
    return $false
}

# The one deprecation message for the v1 -IncludeOptional switch.
function Write-IncludeOptionalWarning {
    param([bool]$IncludeOptional)
    if ($IncludeOptional) {
        Write-Warning '-IncludeOptional is deprecated and ignored: v2 folded the Optional tier into HighVolume (ADR-002). Use -IncludeHighVolume. The switch will be removed in a later release.'
    }
}

function Test-TierSelected {
    param([string]$Tier, [bool]$IncludeHighVolume)
    if ($Tier -eq 'Core') { return $true }
    if ($Tier -eq 'HighVolume') { return $IncludeHighVolume }
    return $false
}

# Resolves a script's -BaselineFile / -IncludeHighVolume parameters into one
# selection object; call it once at setup and pass the result to
# Test-ItemSelected. Stops the script (exit 1) when the file does not exist,
# which is what every caller did before this helper existed.
# -IncludeOptional is the deprecated v1 switch: every script still accepts it
# and passes it here, where it only produces the warning.
#   Map              hashtable "ITEMTYPE|ID" -> bool, or $null for tier mode
#   IncludeHighVolume  the tier switch (tier mode only)
#   Description      "baseline file X.csv" or "Core tier [+ HighVolume]"
#   BaselineFile     the path as given, or ''
function Resolve-BaselineSelection {
    param([string]$BaselineFile, [bool]$IncludeHighVolume, [bool]$IncludeOptional)
    Write-IncludeOptionalWarning $IncludeOptional
    $map = $null
    $description = "Core tier$(if ($IncludeHighVolume) {' + HighVolume'})"
    if (-not [string]::IsNullOrEmpty($BaselineFile)) {
        if (-not (Test-Path $BaselineFile)) {
            Write-Error "Baseline file not found: $BaselineFile (build one with New-LoggingBaseline.ps1 or use a preset)"
            exit 1
        }
        $map = Import-BaselineSelection -Path $BaselineFile
        $description = "baseline file $(Split-Path $BaselineFile -Leaf)"
    }
    return @{
        Map               = $map
        IncludeHighVolume = $IncludeHighVolume
        Description       = $description
        BaselineFile      = "$BaselineFile"
    }
}

# The one predicate: is this item on under this selection?
function Test-ItemSelected {
    param([hashtable]$Selection, [string]$ItemType, [string]$Id, [string]$Tier)
    if ($null -ne $Selection.Map) {
        $key = ("$ItemType|$Id").ToUpper()
        return ($Selection.Map.ContainsKey($key) -and $Selection.Map[$key])
    }
    return (Test-TierSelected -Tier $Tier -IncludeHighVolume $Selection.IncludeHighVolume)
}
