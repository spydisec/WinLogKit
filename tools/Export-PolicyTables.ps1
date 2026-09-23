<#
.SYNOPSIS
    Regenerates the two policy delivery pages: docs\intune-csp.md (the
    kit's baseline in Intune Settings catalog / Policy CSP terms) and
    docs\gpo-paths.md (where each setting lives in a Group Policy Object).
    Run after changing the settings table or tools\policy-map.psd1; CI
    fails if the committed pages drift.

.DESCRIPTION
    Items and values come from WinLogKit.Settings.ps1; CSP names and Group
    Policy paths come from the curated tools\policy-map.psd1. On each page
    every kit item lands in exactly one of two tables: deliverable that
    way, or not (with the reason).

    Requires: Windows PowerShell 5.1+. No admin; writes only the doc pages.
#>
[CmdletBinding()]
param(
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$kitRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $kitRoot 'docs' }

. (Join-Path $kitRoot 'WinLogKit.Settings.ps1')
. (Join-Path $kitRoot 'WinLogKit.Common.ps1')
$map = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'policy-map.psd1')

$docBase = 'https://learn.microsoft.com/windows/client-management/mdm/'
# Link text is the CSP area (the part before the slash), as Microsoft titles the page.
function Format-Doc([string]$Page, [string]$Csp) {
    "[$(($Csp -split '/')[0])]($docBase$Page)"
}
function Format-Name([string]$Name, [string]$Scope) {
    if ($Scope -eq 'DomainController') { return "$Name (DC)" }
    return $Name
}
function Get-Entry([hashtable]$Section, [string]$Key, [string]$What) {
    if (-not $Section.ContainsKey($Key)) { throw "$What is missing from tools\policy-map.psd1." }
    return $Section[$Key]
}
function Write-Page([string]$Name, [string]$Header, [object]$Covered, [string]$Middle, [object]$NotCovered) {
    # Here-strings drop their final newline: add it, or the first row would
    # concatenate onto the table separator.
    $content = $Header + "`n" + ($Covered -join "`n") + "`n" + $Middle + "`n" + ($NotCovered -join "`n") + "`n"
    $path = Join-Path $OutDir $Name
    [System.IO.File]::WriteAllText($path, $content, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "$Name written ($(@($Covered).Count) covered, $(@($NotCovered).Count) not)"
}

$auditMap = @{}; foreach ($k in $map.Audit.Keys) { $auditMap[$k.ToUpper()] = $map.Audit[$k] }
$auditText = @{ 1 = 'Success'; 2 = 'Failure'; 3 = 'Success+Failure' }

$cspYes = New-Object System.Collections.Generic.List[string]
$cspNo  = New-Object System.Collections.Generic.List[string]
$gpYes  = New-Object System.Collections.Generic.List[string]
$gpNo   = New-Object System.Collections.Generic.List[string]

foreach ($sub in $script:BaselineAuditSubcategories) {
    $m = Get-Entry $auditMap $sub.Guid.ToUpper() "Audit subcategory $($sub.Name) ($($sub.Guid))"
    $name = Format-Name $sub.Name $sub.Scope
    $v = Get-AuditSettingValue $sub.Success $sub.Failure
    $cspYes.Add("| $name | Audit | $($sub.Tier) | ``Audit/$($m.Csp)`` | $v ($($auditText[$v])) | $(Format-Doc 'policy-csp-audit' 'Audit') |")
    $category = $map.AuditCategories[($m.Csp -split '_')[0]]
    if ($null -eq $category) { throw "No audit category for $($m.Csp) in tools\policy-map.psd1." }
    $gpYes.Add("| $name | Audit | $($sub.Tier) | $($map.AuditFolder) > $category > $($m.Gp) | $(Format-AuditSetting $v) |")
}

foreach ($rs in $script:BaselineRegistrySettings) {
    $m = Get-Entry $map.Registry $rs.Id "Registry item $($rs.Id)"
    $label = Format-Name $rs.Id $rs.Scope
    if ($m.ContainsKey('Csp')) { $cspYes.Add("| $label | Registry | $($rs.Tier) | ``$($m.Csp)`` | $($m.CspValue) | $(Format-Doc $m.Doc $m.Csp) |") }
    else { $cspNo.Add("| $label | Registry | $($m.NoCsp) |") }
    if ($m.ContainsKey('Gp')) { $gpYes.Add("| $label | Registry | $($rs.Tier) | $($m.Gp) | $($m.GpValue) |") }
    else { $gpNo.Add("| $label | Registry | $($m.NoGp) |") }
}

foreach ($sa in $script:BaselineSmbAuditSettings) {
    $m = Get-Entry $map.Smb $sa.Id "SMB audit item $($sa.Id)"
    $cspYes.Add("| $($sa.Id) | SMB audit | $($sa.Tier) | ``$($m.Csp)`` | 1 (Enabled) | $(Format-Doc $m.Doc $m.Csp) |")
    $gpYes.Add("| $($sa.Id) | SMB audit | $($sa.Tier) | $($m.Gp) | Enabled |")
}

foreach ($ch in $script:BaselineChannels) {
    $kb = [long]($ch.TargetBytes / 1KB)
    if ($map.Channels.ContainsKey($ch.Name)) {
        $m = $map.Channels[$ch.Name]
        $cspYes.Add("| $($ch.Name) | Log size | $($ch.Tier) | ``$($m.Csp)`` | Enabled, $kb KB | $(Format-Doc 'policy-csp-eventlogservice' 'EventLogService') |")
        $gpYes.Add("| $($ch.Name) | Log size | $($ch.Tier) | $($m.Gp) | Enabled, $kb KB |")
    } else {
        $what = 'size'; if ($ch.MustEnable) { $what = 'size or enablement' }
        $cspNo.Add("| $($ch.Name) | Log | No CSP for this log's $what. |")
        $gpNo.Add("| $($ch.Name) | Log | No Group Policy template for this log's $what. |")
    }
}

$adcs = $script:BaselineAdcsAuditFilter.Id
$cspNo.Add("| $adcs | Registry | No CSP, and it needs a CertSvc restart: set it on the CA in a change window (``Enable-LoggingBaseline.ps1`` there). |")
$gpNo.Add("| $adcs | Registry | No Group Policy template, and it needs a CertSvc restart: set it on the CA in a change window (``Enable-LoggingBaseline.ps1`` there). |")

# ---- Settings catalog page ------------------------------------------------

$cspHeader = @'
# Intune Settings catalog

<!-- GENERATED by tools\Export-PolicyTables.ps1 - do not edit by hand.
     CI fails if this page drifts from the settings table and tools\policy-map.psd1. -->

If you deliver policy through the Intune **Settings catalog** rather than
scripts, this is the kit's baseline in those terms. Settings catalog
settings are backed by Microsoft's
[Policy CSPs](https://learn.microsoft.com/windows/client-management/mdm/policy-configuration-service-provider);
each row names the CSP and links its Microsoft page. Find the setting in
the catalog by its name, or set it as a custom OMA-URI:
`./Device/Vendor/MSFT/Policy/Config/<CSP>`. For domain-joined hosts, the
same settings by Group Policy are on [Group Policy paths](gpo-paths.md).

!!! note
    Built from Microsoft's CSP documentation, not yet field-tested in a
    tenant ([#46](https://github.com/spydisec/WinLogKit/issues/46)). Pilot
    on a small device group and check the result with
    `Test-LoggingBaseline.ps1`.

Things to know before you start:

- **The catalog only covers part of the baseline.** Audit policy,
  command-line capture, Windows PowerShell logging, SMB auditing and three
  log sizes have a CSP. Everything in the second table doesn't: keep the
  [remediation pack](deployment.md#intune-workstations-and-cloud-managed-servers)
  for those. The two work together, because the pack only changes what is
  below the baseline and the values here match it.
- **CSPs aren't role-aware.** Rows marked **(DC)** only matter on domain
  controllers; the remediation pack checks the role on each host, a
  Settings catalog profile applies to everything it's assigned to.
- **A policy sets a log size outright.** The kit only ever raises sizes;
  a size policy also lowers a log that was bigger. Set the larger value
  if your hosts already have one.
- **SMB auditing needs Windows 11 24H2 or Windows Server 2025**; older
  versions don't have those settings.
- **Mind the Tier column.** Leave HighVolume rows out unless you apply
  that tier (see [Baselines](baselines.md)).

## Settings with a CSP

| Setting | Type | Tier | CSP | Value | Microsoft doc |
|---|---|---|---|---|---|
'@

$cspMiddle = @'

## Settings without a CSP

Use the remediation pack for these. The AD CS row is the exception, as
noted.

| Setting | Type | Why |
|---|---|---|
'@

# ---- Group Policy page ----------------------------------------------------

$gpHeader = @'
# Group Policy paths

<!-- GENERATED by tools\Export-PolicyTables.ps1 - do not edit by hand.
     CI fails if this page drifts from the settings table and tools\policy-map.psd1. -->

Where each kit setting lives in a Group Policy Object, for domain
administrators building the GPO by hand in the Group Policy Management
Editor. Every path below is under **Computer Configuration > Policies**.
The [GPO pack](deployment.md#gpo-domain-joined-fleets)
(`fleet\New-GpoPack.ps1`) generates the same audit policy and registry
values as files, for LGPO or as a reference. Intune instead? See
[Settings catalog](intune-csp.md).

Things to know before you start:

- **Turn on "Audit: Force audit policy subcategory settings (Windows Vista
  or later) to override audit policy category settings"** (Windows
  Settings > Security Settings > Local Policies > Security Options) in the
  same GPO, so basic audit policy can't override the advanced settings
  below ([Microsoft's guidance](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)).
- **Rows marked (DC)** belong in a GPO linked to the Domain Controllers
  OU. They are busy there: read
  [the DC notes](safety.md#can-i-run-this-on-a-domain-controller) first.
- **PowerShell 7 rows** need PowerShell 7's own administrative template
  in the central store; copy it with `InstallPSCorePolicyDefinitions.ps1`
  from the PowerShell 7 folder, or copy the `.admx` and `.adml` by hand.
- **SMB auditing needs Windows 11 24H2 or Windows Server 2025**; older
  versions ignore those settings.
- **Only the classic logs have a size template.** The other kit logs are
  in the second table: size them with the Intune remediation pack or a
  computer startup script.
- **Mind the Tier column.** Leave HighVolume rows out unless you apply
  that tier (see [Baselines](baselines.md)).
- **Check the result** on a host with `Test-LoggingBaseline.ps1`: it reads
  the effective policy, whatever delivered it.

## Settings with a Group Policy path

| Setting | Type | Tier | Path (under Computer Configuration > Policies) | Value |
|---|---|---|---|---|
'@

$gpMiddle = @'

## Settings Group Policy can't deliver

| Setting | Type | Why |
|---|---|---|
'@

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Write-Page 'intune-csp.md' $cspHeader $cspYes $cspMiddle $cspNo
Write-Page 'gpo-paths.md' $gpHeader $gpYes $gpMiddle $gpNo
exit 0
