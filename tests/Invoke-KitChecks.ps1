<#
.SYNOPSIS
    Kit self-checks, runnable locally and in CI. Exits non-zero on any failure.

.DESCRIPTION
    Runs the Pester 5 suite in tests\Kit.Tests.ps1: script parsing, the
    registry-write tripwire, one definition per helper, settings table
    consistency, the baseline builder, the Intune and GPO packs, preset and
    Reference page drift, ATT&CK coverage, the WEF subscription, rollback
    baseline updates, the PowerShell 7 items and locale-neutral audit
    reading.

    Safe on any machine: nothing is applied and no admin is needed. Pester is
    a development and CI dependency only; the kit's own scripts need no
    modules. If Pester 5 isn't installed, this prints the command to install
    it for the current user.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-KitChecks.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Pinned to Pester 5: version 6 may also be installed side by side, and the
# suite is written and tested against 5.
$pester = Get-Module -ListAvailable -Name Pester |
    Where-Object { $_.Version -ge [version]'5.0' -and $_.Version -lt [version]'6.0' } |
    Sort-Object Version -Descending | Select-Object -First 1
if ($null -eq $pester) {
    Write-Host 'Pester 5 is needed for the self-checks. Install it for the current user, then rerun:' -ForegroundColor Yellow
    Write-Host '  Install-Module Pester -RequiredVersion 5.9.1 -Scope CurrentUser -Force -SkipPublisherCheck'
    exit 1
}
Import-Module $pester.Path -Force

$config = New-PesterConfiguration
$config.Run.Path = Join-Path $PSScriptRoot 'Kit.Tests.ps1'
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $config

Write-Host ''
if ($result.Result -ne 'Passed' -or $result.FailedCount -gt 0) {
    # Setup (BeforeAll) and discovery failures fail blocks or containers, not
    # tests, so count them too rather than reporting "0 failed".
    Write-Host "$($result.FailedCount) check(s) failed, $($result.FailedBlocksCount) setup block(s) failed, $($result.FailedContainersCount) test file(s) failed to load." -ForegroundColor Red
    exit 1
}
Write-Host "All kit checks passed ($($result.PassedCount) passed, $($result.SkippedCount) skipped, Pester $($pester.Version))." -ForegroundColor Green
exit 0
