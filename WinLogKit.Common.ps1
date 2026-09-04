# =============================================================================
# WinLogKit.Common.ps1
# Shared helpers, dot-sourced by the kit scripts right after the settings
# table. Everything here is read-only against the host: host probes, registry
# reads, the audit policy reader and the one selection model (tier switches
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

# -------------------------------------------------------------- selection ---
#
# A selection answers "is this item on?" for every item in the settings
# table. It comes from one of two places, and a baseline CSV always wins:
#   - a selection CSV from New-LoggingBaseline.ps1 (or a preset): listed rows
#     decide, unlisted items are off
#   - the tier switches: Core is always on, HighVolume and Optional only when
#     their switch is given

# Selection map from a selection CSV: "ITEMTYPE|ID" -> bool. The file is
# checked first: the wrong CSV (a Results export, say) must stop the run,
# not quietly select nothing.
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
    return $map
}

function Test-TierSelected {
    param([string]$Tier, [bool]$IncludeHighVolume, [bool]$IncludeOptional)
    if ($Tier -eq 'Core') { return $true }
    if ($Tier -eq 'HighVolume') { return $IncludeHighVolume }
    if ($Tier -eq 'Optional') { return $IncludeOptional }
    return $false
}

# Resolves a script's -BaselineFile / -IncludeHighVolume / -IncludeOptional
# parameters into one selection object; call it once at setup and pass the
# result to Test-ItemSelected. Stops the script (exit 1) when the file does
# not exist, which is what every caller did before this helper existed.
#   Map              hashtable "ITEMTYPE|ID" -> bool, or $null for tier mode
#   IncludeHighVolume, IncludeOptional   the tier switches (tier mode only)
#   Description      "baseline file X.csv" or "Core tier [+ HighVolume] [+ Optional]"
#   BaselineFile     the path as given, or ''
function Resolve-BaselineSelection {
    param([string]$BaselineFile, [bool]$IncludeHighVolume, [bool]$IncludeOptional)
    $map = $null
    $description = "Core tier$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
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
        IncludeOptional   = $IncludeOptional
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
    return (Test-TierSelected -Tier $Tier -IncludeHighVolume $Selection.IncludeHighVolume -IncludeOptional $Selection.IncludeOptional)
}
