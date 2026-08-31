<#
.SYNOPSIS
    Runs Yamato Security's WELA (audit-settings and audit-filesize) as an
    independent second opinion on this host's logging configuration, parses
    the results, reports deviations and archives the raw output as evidence.

.DESCRIPTION
    WELA v2.1.0 command syntax used (verified against WELA.ps1 source):
        .\WELA.ps1 audit-settings -Baseline <YamatoSecurity|ASD|Microsoft_Client|Microsoft_Server> [-OutType std|gui|table]
        .\WELA.ps1 audit-filesize -Baseline YamatoSecurity
    Both write CSVs to the current working directory:
        WELA-Audit-Result.csv    (audit-settings: Category, SubCategory, RuleCount,
                                  RuleCountByLevel, DefaultSetting, CurrentSetting,
                                  RecommendedSetting, Volume, Note)
        WELA-FileSize-Result.csv (audit-filesize: LogFile, CurrentLogSize, MaxLogSize,
                                  Default, Recommended, IsLogFull, LogMode, CorrectSetting)
        UsableRules.csv / UnusableRules.csv (Sigma rules usable with current settings)

    WELA is run in a child Windows PowerShell process so its console encoding
    changes and exit calls cannot affect this script. audit-settings needs
    WELA's .\config\ folder (security_rules.json, eid_subcategory_mapping.csv)
    beside WELA.ps1.

    This script never runs WELA's 'configure' command - applying settings is
    Enable-LoggingBaseline.ps1's job, under change control. Note that WELA's own
    configure sets RestrictSendingNTLMTraffic=2, which BLOCKS outgoing NTLM;
    another reason configuration stays with the kit's enable script.

    Requires: Windows PowerShell 5.1+, local Administrator. Internet access
    only needed if -Download is used.

.PARAMETER WelaPath
    Full path to WELA.ps1. If omitted, looks in .\WELA\WELA.ps1 beside this
    script, then .\WELA.ps1 in the current directory.

.PARAMETER Baseline
    Baseline for audit-settings. One of YamatoSecurity (default), ASD,
    Microsoft_Client, Microsoft_Server. audit-filesize only supports
    YamatoSecurity and is always run with that.

.PARAMETER Download
    If WELA is not found, download WELA.ps1 and its two config files from
    github.com/Yamato-Security/WELA (main branch) into .\WELA\ beside this
    script. Off by default so nothing is fetched without an explicit decision.

.PARAMETER EvidenceDir
    Root folder for evidence. A timestamped subfolder is created per run.
    Default: .\Evidence next to this script.

.EXAMPLE
    .\Invoke-WELACheck.ps1 -Download
    First run on an internet-connected test box: fetch WELA, run both audits.

.EXAMPLE
    .\Invoke-WELACheck.ps1 -WelaPath C:\Tools\WELA\WELA.ps1 -Baseline ASD
    Air-gapped run against a pre-staged WELA copy, ASD baseline.
#>
[CmdletBinding()]
param(
    [string]$WelaPath,
    [ValidateSet('YamatoSecurity', 'ASD', 'Microsoft_Client', 'Microsoft_Server')]
    [string]$Baseline = 'YamatoSecurity',
    [switch]$Download,
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$EvidenceDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($EvidenceDir)) { $EvidenceDir = Join-Path $PSScriptRoot 'Evidence' }

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Error 'Run as local Administrator - WELA audit-settings reads the audit policy via auditpol.'
    exit 1
}

# ------------------------------------------------------- locate / download ---

$welaDir = Join-Path $PSScriptRoot 'WELA'
if ([string]::IsNullOrEmpty($WelaPath)) {
    # Search order: .\WELA\, any .\WELA-* folder (e.g. an unzipped WELA-2.1.0
    # release, newest name first), then WELA.ps1 in the current directory.
    $candidates = @(Join-Path $welaDir 'WELA.ps1')
    # Sort by parsed version, not name: string sort would put 2.9.0 above 2.10.0.
    $versionSort = @{ Expression = {
        $v = $null
        if ([version]::TryParse(($_.Name -replace '^WELA-', ''), [ref]$v)) { $v } else { [version]'0.0' }
    }; Descending = $true }
    foreach ($d in (Get-ChildItem -Path $PSScriptRoot -Directory -Filter 'WELA-*' -ErrorAction SilentlyContinue | Sort-Object -Property $versionSort)) {
        $candidates += Join-Path $d.FullName 'WELA.ps1'
    }
    $candidates += Join-Path (Get-Location).Path 'WELA.ps1'
    foreach ($c in $candidates) {
        if (Test-Path $c) { $WelaPath = $c; break }
    }
}

if ([string]::IsNullOrEmpty($WelaPath) -or -not (Test-Path $WelaPath)) {
    if (-not $Download) {
        Write-Error ("WELA.ps1 not found. Either pass -WelaPath, place WELA in $welaDir, " +
                     'or rerun with -Download to fetch it from github.com/Yamato-Security/WELA.')
        exit 1
    }
    Write-Host 'Downloading WELA from github.com/Yamato-Security/WELA (main branch)...' -ForegroundColor Yellow
    # SystemDefault (0) means the OS chooses TLS 1.2/1.3 - leave that alone.
    # Only when a legacy explicit protocol set excludes TLS 1.2 (possible on
    # old Windows PowerShell 5.1 configurations) do we ADD it; nothing is
    # ever removed, so this cannot downgrade the connection.
    $currentProtocols = [Net.ServicePointManager]::SecurityProtocol
    if ($currentProtocols -ne [Net.SecurityProtocolType]::SystemDefault -and <# DevSkim: ignore DS440020 - SystemDefault check preserves OS negotiation #>
        -not ($currentProtocols -band [Net.SecurityProtocolType]::Tls12)) {  # DevSkim: ignore DS440001,DS440020 - capability probe, not a protocol pin
        [Net.ServicePointManager]::SecurityProtocol = $currentProtocols -bor [Net.SecurityProtocolType]::Tls12  # DevSkim: ignore DS440001,DS440020 - additive minimum-version fix, never downgrades
    }
    New-Item -ItemType Directory -Path (Join-Path $welaDir 'config') -Force | Out-Null
    # Required files hard-fail; Optional covers config files that newer WELA
    # versions may add (e.g. config/baselines.json from WELA PR #358) or drop -
    # a missing optional file is skipped so the download works against any
    # recent WELA main.
    $files = @(
        @{ Path = 'WELA.ps1';                           Required = $true }
        @{ Path = 'config/eid_subcategory_mapping.csv'; Required = $false }
        @{ Path = 'config/security_rules.json';         Required = $false }
        @{ Path = 'config/baselines.json';              Required = $false }
    )
    foreach ($f in $files) {
        $dest = Join-Path $welaDir ($f.Path -replace '/', '\')
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Yamato-Security/WELA/main/$($f.Path)" -OutFile $dest -UseBasicParsing
            Write-Host "  fetched $($f.Path)"
        } catch {
            if ($f.Required) { throw }
            Write-Host "  skipped $($f.Path) (not present in current WELA main)" -ForegroundColor DarkGray
        }
    }
    $WelaPath = Join-Path $welaDir 'WELA.ps1'
}

$welaHome = Split-Path $WelaPath -Parent
if (-not (Test-Path (Join-Path $welaHome 'config\security_rules.json'))) {
    Write-Warning 'WELA config folder not found beside WELA.ps1 - audit-settings will fail. Re-download with -Download or copy the config folder.'
}
Write-Host "Using WELA at: $WelaPath"

# ------------------------------------------------------------ evidence dir ---

$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$runDir = Join-Path $EvidenceDir $stamp
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

function Invoke-Wela {
    param([string[]]$WelaArgs, [string]$StdoutFile)
    # Child process: WELA changes console encoding and can call exit; keep it isolated.
    # Run from WELA's own folder so it finds .\config and drops its CSVs there.
    Push-Location $welaHome
    try {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $WelaPath @WelaArgs *> $StdoutFile
        return $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------- run WELA ---

Write-Host "`nRunning: WELA.ps1 audit-settings -Baseline $Baseline"
$rcSettings = Invoke-Wela -WelaArgs @('audit-settings', '-Baseline', $Baseline) -StdoutFile (Join-Path $runDir 'wela-audit-settings-stdout.txt')

Write-Host 'Running: WELA.ps1 audit-filesize -Baseline YamatoSecurity'
$rcFilesize = Invoke-Wela -WelaArgs @('audit-filesize', '-Baseline', 'YamatoSecurity') -StdoutFile (Join-Path $runDir 'wela-audit-filesize-stdout.txt')

# Archive every CSV WELA produced as raw evidence, then work from the copies.
$welaCsvs = @('WELA-Audit-Result.csv', 'WELA-FileSize-Result.csv', 'UsableRules.csv', 'UnusableRules.csv')
foreach ($csv in $welaCsvs) {
    $src = Join-Path $welaHome $csv
    if (Test-Path $src) { Move-Item -Path $src -Destination (Join-Path $runDir $csv) -Force }
}

# ----------------------------------------------------------- parse results ---

$deviations = New-Object System.Collections.Generic.List[object]

$auditCsv = Join-Path $runDir 'WELA-Audit-Result.csv'
if (Test-Path $auditCsv) {
    foreach ($row in (Import-Csv $auditCsv)) {
        # Deviation = current setting does not satisfy the recommendation.
        # Superset-aware for audit flags: if WELA recommends 'Failure' and the
        # host has 'Success and Failure', that satisfies it (more auditing than
        # recommended is not drift). Other values compare exactly.
        $cur = ("$($row.CurrentSetting)").Trim()
        $rec = ("$($row.RecommendedSetting)").Trim()
        $satisfied = $false
        if ($rec -match 'Success|Failure') {
            $satisfied = $true
            if ($rec -match 'Success' -and $cur -notmatch 'Success') { $satisfied = $false }
            if ($rec -match 'Failure' -and $cur -notmatch 'Failure') { $satisfied = $false }
        } else {
            $satisfied = ($cur -eq $rec)
        }
        if ($rec -ne '' -and -not $satisfied) {
            $deviations.Add([pscustomobject]@{
                Check       = 'audit-settings'
                Item        = "$($row.Category) / $($row.SubCategory)"
                Current     = $cur
                Recommended = $rec
                Volume      = $row.Volume
                SigmaRules  = $row.RuleCount
                Note        = $row.Note
            })
        }
    }
} else {
    Write-Warning "audit-settings produced no CSV (exit code $rcSettings) - see wela-audit-settings-stdout.txt in the evidence folder."
}

$sizeCsv = Join-Path $runDir 'WELA-FileSize-Result.csv'
if (Test-Path $sizeCsv) {
    foreach ($row in (Import-Csv $sizeCsv)) {
        if ("$($row.CorrectSetting)".Trim() -eq 'N') {
            $deviations.Add([pscustomobject]@{
                Check       = 'audit-filesize'
                Item        = $row.LogFile
                Current     = "max $($row.MaxLogSize), mode $($row.LogMode)"
                Recommended = $row.Recommended
                Volume      = ''
                SigmaRules  = ''
                Note        = "current usage $($row.CurrentLogSize); full=$($row.IsLogFull)"
            })
        }
    }
} else {
    Write-Warning "audit-filesize produced no CSV (exit code $rcFilesize) - see wela-audit-filesize-stdout.txt in the evidence folder."
}

# ----------------------------------------------------------------- report ---

Write-Host ''
if ($deviations.Count -eq 0) {
    Write-Host "WELA reports no deviations from the $Baseline baseline." -ForegroundColor Green
} else {
    Write-Host "WELA found $($deviations.Count) deviation(s) from baseline:" -ForegroundColor Yellow
    $deviations | Format-Table Check, Item, Current, Recommended -AutoSize | Out-String -Width 200 | Write-Host
    Write-Host ('Reminder: HighVolume-tier items deliberately not deployed will appear here as deviations - ' +
                'cross-check against the PENDING DECISION list from Enable-LoggingBaseline.ps1.') -ForegroundColor DarkGray
}

$devCsv = Join-Path $runDir 'WELA-Deviations.csv'
$deviations | Export-Csv -Path $devCsv -NoTypeInformation -Encoding UTF8

Write-Host ''
Write-Host "Evidence archived (raw WELA CSVs + console output + deviation summary):"
Write-Host "  $runDir"

if ($deviations.Count -gt 0) { exit 1 } else { exit 0 }
