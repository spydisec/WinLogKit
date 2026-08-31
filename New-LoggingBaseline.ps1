<#
.SYNOPSIS
    Interactive baseline builder. Walks through every setting in the kit,
    shows the kit's recommendation plus the volume/stability risk, lets you
    include or exclude each one, and writes your choices to a baseline CSV.

.DESCRIPTION
    Changes NOTHING on the host - it only writes a CSV. The CSV is then the
    input for the other two scripts:

        .\New-LoggingBaseline.ps1                             # build MyBaseline.csv
        .\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv
        .\Test-LoggingBaseline.ps1   -BaselineFile .\MyBaseline.csv

    The kit recommendation (the reference baseline) is shown per item and is
    the default answer, so pressing Enter through the whole run reproduces
    the recommended set. Items with a volume or stability risk display that
    risk before you answer, so nothing heavy gets selected blind.

    The CSV is deliberately human-friendly: open it in Excel, flip Selected
    between Y and N, and re-run Enable/Test with the edited file. Columns
    other than ItemType, Id and Selected are context for the reader and are
    ignored by the scripts.

    Keys during selection:
        Enter  accept the shown default for this item
        y / n  include / exclude this item
        a      accept defaults for every remaining item in this section
        q      abort without writing anything

    Requires: Windows PowerShell 5.1+. No admin needed (nothing is changed).

.PARAMETER OutFile
    Where to write the baseline CSV. Default: .\MyBaseline.csv next to this
    script. Refuses to overwrite an existing file unless -Force.

.PARAMETER AcceptRecommended
    Non-interactive: write the CSV with every item set to its recommended
    default (Core = Y, HighVolume/Optional = N) and exit. Use this to get a
    starting file to edit in Excel.

.PARAMETER IncludeHighVolume
    Shift the default for HighVolume items to Y (you still confirm each one
    interactively; with -AcceptRecommended they are written as Y).

.PARAMETER IncludeOptional
    Same as above for Optional tier items.

.PARAMETER Force
    Overwrite an existing OutFile.

.EXAMPLE
    .\New-LoggingBaseline.ps1
    Full interactive walk-through.

.EXAMPLE
    .\New-LoggingBaseline.ps1 -AcceptRecommended -IncludeHighVolume -OutFile .\ServerBaseline.csv
    Write the recommended-plus-high-volume set without prompting, for editing in Excel.
#>
[CmdletBinding()]
param(
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutFile,
    [switch]$AcceptRecommended,
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    [switch]$Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutFile)) { $OutFile = Join-Path $PSScriptRoot 'MyBaseline.csv' }

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')

if ((Test-Path $OutFile) -and -not $Force) {
    Write-Error "$OutFile already exists. Use -Force to overwrite, or pick another -OutFile."
    exit 1
}

function Get-DefaultSelected {
    # The kit recommendation: Core is in, heavier tiers are opt-in.
    param([string]$Tier)
    if ($Tier -eq 'Core') { return $true }
    if ($Tier -eq 'HighVolume') { return [bool]$IncludeHighVolume }
    if ($Tier -eq 'Optional') { return [bool]$IncludeOptional }
    return $false
}

function Get-ItemField {
    param([hashtable]$Item, [string]$Field)
    if ($Item.ContainsKey($Field)) { return [string]$Item[$Field] }
    return ''
}

# ---- flatten the settings table into one uniform selection list -------------

$items = New-Object System.Collections.Generic.List[object]

foreach ($ch in $script:BaselineChannels) {
    $items.Add([pscustomobject]@{
        Section  = 'Event log channels'
        ItemType = 'Channel'
        Id       = $ch.Name
        Name     = $ch.Name
        Tier     = $ch.Tier
        Scope    = 'All'
        Purpose  = $ch.Purpose
        Risk     = (Get-ItemField $ch 'Risk')
        Categories = ($ch.Categories -join '; ')
    })
}
foreach ($sub in $script:BaselineAuditSubcategories) {
    $items.Add([pscustomobject]@{
        Section  = 'Advanced audit policy subcategories'
        ItemType = 'AuditPolicy'
        Id       = $sub.Guid.ToUpper()
        Name     = $sub.Name
        Tier     = $sub.Tier
        Scope    = $sub.Scope
        Purpose  = $sub.Purpose
        Risk     = (Get-ItemField $sub 'Risk')
        Categories = ($sub.Categories -join '; ')
    })
}
foreach ($rs in $script:BaselineRegistrySettings) {
    $items.Add([pscustomobject]@{
        Section  = 'Registry settings'
        ItemType = 'Registry'
        Id       = $rs.Id
        Name     = "$($rs.Path)\$($rs.Name) = $($rs.Value)"
        Tier     = $rs.Tier
        Scope    = $rs.Scope
        Purpose  = $rs.Purpose
        Risk     = (Get-ItemField $rs 'Risk')
        Categories = ($rs.Categories -join '; ')
    })
}
foreach ($sa in $script:BaselineSmbAuditSettings) {
    $items.Add([pscustomobject]@{
        Section  = 'SMB audit settings (Windows Server 2025+)'
        ItemType = 'SmbAudit'
        Id       = $sa.Id
        Name     = "$($sa.Side): $($sa.Id) = $($sa.Value)"
        Tier     = $sa.Tier
        Scope    = $sa.Scope
        Purpose  = $sa.Purpose
        Risk     = 'No effect on OSes before Windows Server 2025 / Windows 11 24H2 (reported NOT APPLICABLE there). Audit-only; nothing is blocked.'
        Categories = ($sa.Categories -join '; ')
    })
}
$af = $script:BaselineAdcsAuditFilter
$items.Add([pscustomobject]@{
    Section  = 'Registry settings'
    ItemType = 'Registry'
    Id       = $af.Id
    Name     = 'AD CS AuditFilter = 127 (only applies when Certificate Services is installed; needs CertSvc restart)'
    Tier     = $af.Tier
    Scope    = $af.Scope
    Purpose  = $af.Purpose
    Risk     = 'Takes effect only after a CertSvc service restart, which the kit never performs itself - plan a change window.'
    Categories = ($af.Categories -join '; ')
})

# ---- selection --------------------------------------------------------------

$selections = @{}   # "ItemType|Id" -> bool

if ($AcceptRecommended) {
    foreach ($it in $items) { $selections["$($it.ItemType)|$($it.Id)"] = Get-DefaultSelected $it.Tier }
    Write-Host "Non-interactive: recommended defaults applied (Core = Y$(if ($IncludeHighVolume) {', HighVolume = Y'})$(if ($IncludeOptional) {', Optional = Y'}))."
} else {
    Write-Host ''
    Write-Host 'Build your logging baseline' -ForegroundColor White
    Write-Host 'The kit recommendation is the default - press Enter to accept it per item.'
    Write-Host 'Keys: [Enter]=default  [y]=include  [n]=exclude  [a]=defaults for rest of section  [q]=abort'
    Write-Host ''

    foreach ($section in @('Event log channels', 'Advanced audit policy subcategories', 'Registry settings', 'SMB audit settings (Windows Server 2025+)')) {
        $sectionItems = @($items | Where-Object { $_.Section -eq $section })
        Write-Host "=== $section ($($sectionItems.Count) items) ===" -ForegroundColor White
        $acceptRest = $false
        $i = 0
        foreach ($it in $sectionItems) {
            $i++
            $default = Get-DefaultSelected $it.Tier
            $key = "$($it.ItemType)|$($it.Id)"

            if ($acceptRest) { $selections[$key] = $default; continue }

            $defText = 'N'; if ($default) { $defText = 'Y' }
            $tierTag = "[$($it.Tier)]"
            $scopeTag = ''
            if ($it.Scope -eq 'DomainController') { $scopeTag = ' [DC only]' }

            Write-Host ''
            Write-Host ("({0}/{1}) {2} {3}{4}" -f $i, $sectionItems.Count, $it.Name, $tierTag, $scopeTag) -ForegroundColor Cyan
            Write-Host ("      {0}" -f $it.Purpose) -ForegroundColor Gray
            if ($it.Risk -ne '') {
                Write-Host ("      RISK: {0}" -f $it.Risk) -ForegroundColor Yellow
            }

            $answered = $false
            while (-not $answered) {
                $resp = Read-Host ("      Include? recommended [{0}] (Enter/y/n/a/q)" -f $defText)
                switch -Regex ($resp.Trim()) {
                    '^$'      { $selections[$key] = $default; $answered = $true }
                    '^[Yy]$'  { $selections[$key] = $true;    $answered = $true }
                    '^[Nn]$'  { $selections[$key] = $false;   $answered = $true }
                    '^[Aa]$'  { $selections[$key] = $default; $answered = $true; $acceptRest = $true }
                    '^[Qq]$'  { Write-Host 'Aborted - nothing written.' -ForegroundColor Yellow; exit 1 }
                    default   { Write-Host '      Please answer Enter, y, n, a or q.' -ForegroundColor DarkYellow }
                }
            }
        }
        Write-Host ''
    }
}

# ---- write the CSV ----------------------------------------------------------

$outRows = foreach ($it in $items) {
    $sel = 'N'; if ($selections["$($it.ItemType)|$($it.Id)"]) { $sel = 'Y' }
    $rec = 'N'; if (Get-DefaultSelected $it.Tier) { $rec = 'Y' }
    [pscustomobject]@{
        ItemType    = $it.ItemType
        Id          = $it.Id
        Name        = $it.Name
        Tier        = $it.Tier
        Scope       = $it.Scope
        Recommended = $rec
        Selected    = $sel
        Risk        = $it.Risk
        Purpose     = $it.Purpose
        Categories  = $it.Categories
    }
}
$outRows | Export-Csv -Path $OutFile -NoTypeInformation -Encoding UTF8

# ---- summary ----------------------------------------------------------------

$selectedCount = @($outRows | Where-Object { $_.Selected -eq 'Y' }).Count
$offRecommended = @($outRows | Where-Object { $_.Selected -ne $_.Recommended })
$riskySelected  = @($outRows | Where-Object { $_.Selected -eq 'Y' -and $_.Risk -ne '' })

Write-Host ''
Write-Host "Baseline written: $OutFile ($selectedCount of $($outRows.Count) items selected)" -ForegroundColor Green

if ($offRecommended.Count -gt 0) {
    Write-Host ''
    Write-Host 'Differs from the kit recommendation on:' -ForegroundColor Cyan
    $offRecommended | ForEach-Object { Write-Host ("  {0,-3} (recommended {1}): {2}" -f $_.Selected, $_.Recommended, $_.Name) -ForegroundColor Cyan }
}
if ($riskySelected.Count -gt 0) {
    Write-Host ''
    Write-Host 'Selected items with a volume or stability note - pilot these before fleet rollout:' -ForegroundColor Yellow
    $riskySelected | ForEach-Object { Write-Host ("  - {0}" -f $_.Name) -ForegroundColor Yellow }
}

Write-Host ''
Write-Host 'Next steps (you can first edit the CSV in Excel - flip Selected between Y and N):'
Write-Host "  .\Enable-LoggingBaseline.ps1 -BaselineFile `"$OutFile`" -WhatIf   # preview"
Write-Host "  .\Enable-LoggingBaseline.ps1 -BaselineFile `"$OutFile`"           # apply"
Write-Host "  .\Test-LoggingBaseline.ps1   -BaselineFile `"$OutFile`"           # verify"
exit 0
