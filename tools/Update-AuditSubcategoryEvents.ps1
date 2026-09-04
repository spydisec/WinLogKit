<#
.SYNOPSIS
    Regenerates data\wef\audit_subcategory_events.csv: the complete list of
    Security event IDs each advanced audit policy subcategory in the kit's
    settings table can emit, taken from Microsoft's per-subcategory
    documentation pages, plus the Eventlog-service events that are always
    on (1100, 1102, 1104, 1105, 1108). Run when Microsoft's pages change; the snapshot is what
    New-WefSubscription.ps1 -Filter Baseline reads at run time.

.DESCRIPTION
    Why a snapshot: a WEF filter derived from the baseline must forward
    EVERY event a selected subcategory can produce, or it silently drops
    events the baseline deliberately turned on. The ATT&CK event map is
    curated for detection value, not completeness, so it is the wrong
    source for this. Microsoft documents each subcategory with an
    "Events List" of "NNNN (S/F):" entries - that is the authoritative,
    complete set, and this tool captures it with provenance (URL and
    fetch date per row).

    Requires: Windows PowerShell 5.1 or PowerShell 7, internet access. No
    admin; writes only the data file. Nothing else in the kit fetches.
#>
[CmdletBinding()]
param([string]$OutFile)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$kitRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrEmpty($OutFile)) { $OutFile = Join-Path (Join-Path (Join-Path $kitRoot 'data') 'wef') 'audit_subcategory_events.csv' }
. (Join-Path $kitRoot 'WinLogKit.Settings.ps1')

$base = 'https://learn.microsoft.com/windows/security/threat-protection/auditing/'
# Explicit name -> page slug map. Microsoft's slugs are not derivable for
# every name ("Other Logon/Logoff Events" -> audit-other-logonlogoff-events,
# "Plug and Play" -> audit-pnp-activity), so they are listed, not computed.
$slugs = @{
    'Account Lockout'                    = 'audit-account-lockout'
    'Audit Policy Change'                = 'audit-audit-policy-change'
    'Authentication Policy Change'       = 'audit-authentication-policy-change'
    'Certification Services'             = 'audit-certification-services'
    'Computer Account Management'        = 'audit-computer-account-management'
    'Credential Validation'              = 'audit-credential-validation'
    'Directory Service Access'           = 'audit-directory-service-access'
    'Directory Service Changes'          = 'audit-directory-service-changes'
    'Distribution Group Management'      = 'audit-distribution-group-management'
    'File Share'                         = 'audit-file-share'
    'Filtering Platform Connection'      = 'audit-filtering-platform-connection'
    'IPsec Driver'                       = 'audit-ipsec-driver'
    'Kerberos Authentication Service'    = 'audit-kerberos-authentication-service'
    'Kerberos Service Ticket Operations' = 'audit-kerberos-service-ticket-operations'
    'Logoff'                             = 'audit-logoff'
    'Logon'                              = 'audit-logon'
    'Other Account Management Events'    = 'audit-other-account-management-events'
    'Other Logon/Logoff Events'          = 'audit-other-logonlogoff-events'
    'Other Object Access Events'         = 'audit-other-object-access-events'
    'Other Policy Change Events'         = 'audit-other-policy-change-events'
    'Other System Events'                = 'audit-other-system-events'
    'Plug and Play'                      = 'audit-pnp-activity'
    'Process Creation'                   = 'audit-process-creation'
    'RPC Events'                         = 'audit-rpc-events'
    'Removable Storage'                  = 'audit-removable-storage'
    'SAM'                                = 'audit-sam'
    'Security Group Management'          = 'audit-security-group-management'
    'Security State Change'              = 'audit-security-state-change'
    'Security System Extension'          = 'audit-security-system-extension'
    'Sensitive Privilege Use'            = 'audit-sensitive-privilege-use'
    'Special Logon'                      = 'audit-special-logon'
    'System Integrity'                   = 'audit-system-integrity'
    'User Account Management'            = 'audit-user-account-management'
}

# Same additive TLS 1.2 handling as the kit's other downloads.
$currentProtocols = [Net.ServicePointManager]::SecurityProtocol
if ($currentProtocols -ne [Net.SecurityProtocolType]::SystemDefault -and <# DevSkim: ignore DS440020 - SystemDefault check preserves OS negotiation #>
    -not ($currentProtocols -band [Net.SecurityProtocolType]::Tls12)) {  # DevSkim: ignore DS440001,DS440020 - capability probe, not a protocol pin
    [Net.ServicePointManager]::SecurityProtocol = $currentProtocols -bor [Net.SecurityProtocolType]::Tls12  # DevSkim: ignore DS440001,DS440020 - additive minimum-version fix, never downgrades
}

function Get-EventIdsFromPage {
    # Microsoft lists events as "4624 (S): text" (S = success, F = failure,
    # "S, F" = both, "-" = unclassified); a few pages (Certification
    # Services) use the bare "4868: text" form. Both end in a colon, and
    # Security event IDs live in 1xxx and 4xxx-6xxx, which keeps years and
    # other four-digit numbers out.
    param([string]$Url)
    $html = (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
    $text = [System.Net.WebUtility]::HtmlDecode(($html -replace '<[^>]+>', ' '))
    $ids = [regex]::Matches($text, '\b(1\d{3}|[4-6]\d{3})\s?(?:\((?:S|F|S, F|-)\))?:') | ForEach-Object { [int]$_.Groups[1].Value } | Sort-Object -Unique
    return @($ids)
}

$fetched = (Get-Date).ToString('yyyy-MM-dd')
$rows = New-Object System.Collections.Generic.List[object]

foreach ($sub in ($script:BaselineAuditSubcategories | Sort-Object Name)) {
    if (-not $slugs.ContainsKey($sub.Name)) { throw "No Microsoft page slug mapped for subcategory '$($sub.Name)' - add it to the slug table." }
    $url = $base + $slugs[$sub.Name]
    $ids = @(Get-EventIdsFromPage $url)
    if ($ids.Count -eq 0) { throw "No event IDs found on $url - page layout may have changed." }
    Write-Host ('{0,-36} {1,3} events: {2}' -f $sub.Name, $ids.Count, ($ids -join ' '))
    foreach ($id in $ids) {
        $rows.Add([pscustomobject]@{ Guid = $sub.Guid.ToUpper(); Subcategory = $sub.Name; EventID = $id; SourceUrl = $url; Fetched = $fetched })
    }
}

# Eventlog service events: not governed by any subcategory, always emitted,
# and the tamper signals a SIEM must never lose (1102 = audit log cleared).
$otherUrl = $base + 'other-events'
$otherIds = @(Get-EventIdsFromPage $otherUrl | Where-Object { $_ -ge 1100 -and $_ -le 1199 })
if ($otherIds.Count -eq 0) { throw "No 11xx Eventlog events found on $otherUrl" }
Write-Host ('{0,-36} {1,3} events: {2}' -f 'Eventlog service (always on)', $otherIds.Count, ($otherIds -join ' '))
foreach ($id in $otherIds) {
    $rows.Add([pscustomobject]@{ Guid = 'ALWAYS'; Subcategory = 'Eventlog service (always on)'; EventID = $id; SourceUrl = $otherUrl; Fetched = $fetched })
}

# Sourced supplement: events Microsoft documents in its downloadable
# "Windows 10 and Windows Server 2016 security auditing and monitoring
# reference" (the per-event spreadsheet) but that are missing from the Learn
# subcategory page. Kept here, not in a second file, so the snapshot stays one
# CSV with a source on every row. Add a row only with a Microsoft source.
$supplementUrl = 'https://www.microsoft.com/download/details.aspx?id=52630'
$supplement = @(
    @{ Guid = '0CCE9221-69AE-11D9-BED3-505054503030'; Subcategory = 'Certification Services'; EventID = 4899 }   # A Certificate Services template was updated
    @{ Guid = '0CCE9221-69AE-11D9-BED3-505054503030'; Subcategory = 'Certification Services'; EventID = 4900 }   # Certificate Services template security was updated
)
foreach ($s in $supplement) {
    $dup = $rows | Where-Object { $_.Guid -eq $s.Guid -and $_.EventID -eq $s.EventID }
    if (-not $dup) {
        Write-Host ('{0,-36} + {1} (supplement: Microsoft auditing reference spreadsheet)' -f $s.Subcategory, $s.EventID)
        $rows.Add([pscustomobject]@{ Guid = $s.Guid; Subcategory = $s.Subcategory; EventID = $s.EventID; SourceUrl = $supplementUrl; Fetched = $fetched })
    }
}
$sorted = $rows | Sort-Object Subcategory, EventID
$rows = New-Object System.Collections.Generic.List[object]
foreach ($r in $sorted) { $rows.Add($r) }

$outParent = Split-Path $OutFile -Parent
if (-not [string]::IsNullOrEmpty($outParent)) { New-Item -ItemType Directory -Path $outParent -Force | Out-Null }
$csv = ($rows | ConvertTo-Csv -NoTypeInformation) -join "`n"
[System.IO.File]::WriteAllText($OutFile, $csv + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Host "Written: $OutFile ($($rows.Count) rows)" -ForegroundColor Green
exit 0
