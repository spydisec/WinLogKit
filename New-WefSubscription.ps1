<#
.SYNOPSIS
    Generates a source-initiated Windows Event Forwarding (WEF) subscription
    XML from the kit's settings table (or a baseline selection CSV), so the
    events this kit enables can be collected centrally on a Windows Event
    Collector (WEC) - agentless, native, no third party components.

.DESCRIPTION
    Where this sits in the pipeline: the kit makes hosts PRODUCE the right
    events (generate); WEF/WEC moves selected events to a collector's
    ForwardedEvents log (transport); your SIEM picks them up from the
    collector (ingest - out of scope for this kit by design).

    The subscription query is evaluated ON EACH SOURCE by the forwarding
    service before anything is sent, so filtering here is filtering at the
    origin: it saves network, collector disk, agent work and SIEM ingestion
    all at once. Two filter modes:

      -Filter Channel  (default) forwards every event of each selected
                       channel: <Select Path="Security">*</Select>. The
                       baseline's channel selection is the coarse filter.
                       Simple, complete, and the right first deployment.

      -Filter Baseline forwards, for the Security channel, exactly the event
                       IDs the baseline's enabled audit subcategories can
                       produce (from data\wef\audit_subcategory_events.csv,
                       Microsoft's documented per-subcategory event lists),
                       plus the always-on Eventlog-service events (1100, 1102,
                       1104, 1105, 1108: service stopped, log cleared, log full). Every other
                       channel is still forwarded whole, because the
                       baseline enables those channels as units. Nothing the
                       baseline turns on is dropped; nothing it did not turn
                       on is forwarded. Suppress rules from the settings
                       table ($BaselineWefSuppress) are appended per channel.

    The generated XML records which mode produced it. A sidecar file
    <SubscriptionId>.expected-eventids.csv lists what the subscription
    should deliver per channel; Test-WefFilter.ps1 reads it on the collector
    to prove the filter is in effect (unexpected IDs = filter not applied).

    -Validate runs each generated query through this machine's event log
    engine (Get-WinEvent -FilterXml). A query that does not parse fails the
    run and nothing is written. "No events found" means the syntax is fine.
    A channel this machine cannot read (Security without admin) or does not
    have (PowerShellCore without PowerShell 7) is reported UNCHECKED: its
    query was not judged either way, so run -Validate elevated on a host
    that has the channels for full coverage.

    Setup after generation (printed again by the script):
      Collector (a domain-joined server):
        winrm qc -q     (WinRM listener first - sources connect to it)
        wecutil qc /q
        wecutil cs .\WEF\<SubscriptionId>.xml
      Sources (via GPO):
        Computer Configuration > Administrative Templates > Windows Components
        > Event Forwarding > Configure target Subscription Manager:
          Server=http://<collector-fqdn>:5985/wsman/SubscriptionManager/WEC,Refresh=60 (DevSkim: ignore DS137138 - documented WinRM default; WEF payloads are Kerberos message-level encrypted over HTTP; HTTPS:5986 optional)
        For the Security log, add NETWORK SERVICE to the "Event Log Readers"
        group on each source (or grant channel access), or forwarding of
        Security events will silently fail.

    Transport defaults (ContentFormat, batching, heartbeat, source SDDL) live
    in LoggingBaseline.Settings.ps1 ($BaselineWefDefaults); parameters here
    override them per run.

    Generation is read-only: no admin needed, nothing on the host changes.

.PARAMETER BaselineFile
    Optional selection CSV from New-LoggingBaseline.ps1. Selected = Y channel
    rows are forwarded; Selected = Y audit-subcategory rows drive the Security
    filter in Baseline mode. Without it, the kit's Core tier is used (plus
    HighVolume/Optional items if the matching switch is given).

.PARAMETER Filter
    Channel (default): whole-channel forwarding. Baseline: Security events
    filtered to the enabled subcategories' documented event IDs.

.PARAMETER Validate
    Parse every generated query with this machine's event log engine.

.PARAMETER SubscriptionId
    Subscription name shown in wecutil / Event Viewer. Default: WinLogKit-Baseline.

.PARAMETER OutDir
    Where the XML and sidecar are written. Default: .\WEF next to this script.

.PARAMETER ContentFormat
    Events (binary, locale-independent, smaller on the wire - default) or
    RenderedText (human-readable message text included).

.PARAMETER MaxLatencySeconds
    Delivery batching latency. Default 30 (near-real-time push).

.PARAMETER HeartbeatSeconds
    Source heartbeat interval so dead sources are noticeable. Default 3600.

.PARAMETER ReadExistingEvents
    Also forward events already in the source logs when a source first
    subscribes (one-time backfill; can be a large burst on first connect).

.PARAMETER AllowedSourceDomainComputersSddl
    SDDL controlling which computers may forward. Default grants Domain
    Computers and Network Service (Microsoft's documented default).

.EXAMPLE
    .\New-WefSubscription.ps1
    Core-tier channels, whole-channel forwarding, into .\WEF\WinLogKit-Baseline.xml.

.EXAMPLE
    .\New-WefSubscription.ps1 -BaselineFile .\presets\spydi_Server_Minimal.csv -Filter Baseline -Validate
    Security filtered to exactly what that preset enables; every query parsed locally.

.EXAMPLE
    .\New-WefSubscription.ps1 -BaselineFile .\presets\ASD.csv -SubscriptionId ASD-Baseline
    Subscription covering exactly the channels the ASD preset selects.
#>
[CmdletBinding()]
param(
    [string]$BaselineFile,
    [ValidateSet('Channel', 'Baseline')]
    [string]$Filter = 'Channel',
    [switch]$Validate,
    [string]$SubscriptionId = 'WinLogKit-Baseline',
    # Default resolved in the body: $PSScriptRoot is not reliably available
    # during param-default evaluation under powershell.exe -File.
    [string]$OutDir,
    # Transport defaults come from $BaselineWefDefaults in the settings table;
    # any value given here overrides them for this run.
    [string]$ContentFormat,
    [int]$MaxLatencySeconds,
    [int]$MaxItems,
    [int]$HeartbeatSeconds,
    [switch]$ReadExistingEvents,
    [switch]$IncludeHighVolume,
    [switch]$IncludeOptional,
    [string]$AllowedSourceDomainComputersSddl
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $PSScriptRoot 'WEF' }

. (Join-Path $PSScriptRoot 'LoggingBaseline.Settings.ps1')

$wefDefaults = $script:BaselineWefDefaults
if ([string]::IsNullOrEmpty($ContentFormat)) { $ContentFormat = $wefDefaults.ContentFormat }
if ($ContentFormat -notin @('Events', 'RenderedText')) {
    Write-Error "ContentFormat must be 'Events' or 'RenderedText' (got '$ContentFormat')."
    exit 1
}
if ($MaxLatencySeconds -le 0) { $MaxLatencySeconds = $wefDefaults.MaxLatencySeconds }
if ($MaxItems -le 0)          { $MaxItems          = $wefDefaults.MaxItems }
if ($HeartbeatSeconds -le 0)  { $HeartbeatSeconds  = $wefDefaults.HeartbeatSeconds }
if ([string]::IsNullOrEmpty($AllowedSourceDomainComputersSddl)) { $AllowedSourceDomainComputersSddl = $wefDefaults.AllowedSourceDomainComputersSddl }

# Windows caps an event query at 32 expressions per Select/Suppress
# (https://learn.microsoft.com/windows/win32/wes/queryschema-querytype-complextype).
# A single EventID test is one expression, a range is two; packing to 20
# leaves headroom for the surrounding boolean structure.
$maxExpressionsPerSelect = 20

# ------------------------------------------------------ selection (what) ---

$channels = New-Object System.Collections.Generic.List[string]
$subcategoryGuids = New-Object System.Collections.Generic.List[string]

if (-not [string]::IsNullOrEmpty($BaselineFile)) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile (build one with New-LoggingBaseline.ps1 or use a preset)"
        exit 1
    }
    foreach ($row in (Import-Csv $BaselineFile)) {
        if ("$($row.Selected)".Trim() -notmatch '^(Y|YES|TRUE|1)$') { continue }
        if ($row.ItemType -eq 'Channel')     { $channels.Add($row.Id) }
        if ($row.ItemType -eq 'AuditPolicy') { $subcategoryGuids.Add($row.Id.ToUpper()) }
    }
    $sourceDesc = "baseline file $(Split-Path $BaselineFile -Leaf)"
} else {
    foreach ($ch in $script:BaselineChannels) {
        $take = ($ch.Tier -eq 'Core')
        if ($ch.Tier -eq 'HighVolume' -and $IncludeHighVolume) { $take = $true }
        if ($ch.Tier -eq 'Optional' -and $IncludeOptional) { $take = $true }
        if ($take) { $channels.Add($ch.Name) }
    }
    foreach ($sub in $script:BaselineAuditSubcategories) {
        $take = ($sub.Tier -eq 'Core')
        if ($sub.Tier -eq 'HighVolume' -and $IncludeHighVolume) { $take = $true }
        if ($sub.Tier -eq 'Optional' -and $IncludeOptional) { $take = $true }
        if ($take) { $subcategoryGuids.Add($sub.Guid.ToUpper()) }
    }
    $sourceDesc = "kit Core tier$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
}

if ($channels.Count -eq 0) {
    Write-Error 'No channels selected - nothing to forward.'
    exit 1
}

# ------------------------------------------- Security filter (Baseline mode) ---

# Expected delivery per channel, for the sidecar: channel -> list of event
# IDs, or the single entry '*' for whole-channel forwarding.
$expected = [ordered]@{}
foreach ($chName in $channels) { $expected[$chName] = @('*') }
$coverageLines = New-Object System.Collections.Generic.List[string]
$securityIds = @()

if ($Filter -eq 'Baseline') {
    if ($channels -notcontains 'Security') {
        Write-Error 'Baseline filter mode needs the Security channel in the selection (it is the channel being filtered).'
        exit 1
    }
    $mapPath = Join-Path (Join-Path (Join-Path $PSScriptRoot 'data') 'wef') 'audit_subcategory_events.csv'
    if (-not (Test-Path $mapPath)) { Write-Error "Event map not found: $mapPath (regenerate with tools\Update-AuditSubcategoryEvents.ps1)"; exit 1 }
    $eventMap = Import-Csv $mapPath
    $idSet = New-Object 'System.Collections.Generic.SortedSet[int]'
    $subNames = @{}
    foreach ($sub in $script:BaselineAuditSubcategories) { $subNames[$sub.Guid.ToUpper()] = $sub.Name }

    foreach ($guid in ($subcategoryGuids | Sort-Object -Unique)) {
        $rows = @($eventMap | Where-Object { $_.Guid -eq $guid })
        $name = if ($subNames.ContainsKey($guid)) { $subNames[$guid] } else { $guid }
        if ($rows.Count -eq 0) {
            # Refusing is the safe failure: a filter that cannot name this
            # subcategory's events would silently drop everything it produces.
            Write-Error "No documented event IDs for enabled subcategory '$name' in $mapPath. Regenerate the snapshot (tools\Update-AuditSubcategoryEvents.ps1) before using -Filter Baseline."
            exit 1
        }
        foreach ($r in $rows) { [void]$idSet.Add([int]$r.EventID) }
        $coverageLines.Add(('  {0,-36} {1,3} event IDs' -f $name, $rows.Count))
    }
    $alwaysRows = @($eventMap | Where-Object { $_.Guid -eq 'ALWAYS' })
    foreach ($r in $alwaysRows) { [void]$idSet.Add([int]$r.EventID) }
    $coverageLines.Add(('  {0,-36} {1,3} event IDs (always forwarded)' -f 'Eventlog service', $alwaysRows.Count))
    $securityIds = @($idSet)
    $expected['Security'] = $securityIds
}

# --------------------------------------------------------------- build XML ---

function ConvertTo-XmlEscaped { param([string]$s) [System.Security.SecurityElement]::Escape($s) }

function ConvertTo-EventIdSelectXml {
    # Sorted IDs -> as few Select elements as the 32-expression cap allows:
    # consecutive runs collapse to a range (two expressions), singles stay as
    # EventID=N (one). '<' must be written as &lt; inside the query XML;
    # '>' is legal as-is.
    param([int[]]$Ids, [string]$Path, [int]$MaxExpressions)
    $terms = New-Object System.Collections.Generic.List[object]
    $i = 0
    while ($i -lt $Ids.Count) {
        $start = $Ids[$i]; $end = $start
        while (($i + 1) -lt $Ids.Count -and $Ids[$i + 1] -eq ($end + 1)) { $i++; $end = $Ids[$i] }
        if ($end -gt $start) { $terms.Add(@{ Text = "(EventID >= $start and EventID &lt;= $end)"; Cost = 2 }) }
        else                 { $terms.Add(@{ Text = "EventID=$start"; Cost = 1 }) }
        $i++
    }
    $selects = New-Object System.Collections.Generic.List[string]
    $group = New-Object System.Collections.Generic.List[string]
    $cost = 0
    foreach ($t in $terms) {
        if ($cost + $t.Cost -gt $MaxExpressions -and $group.Count -gt 0) {
            $selects.Add("      <Select Path=`"$Path`">*[System[($($group -join ' or '))]]</Select>")
            $group.Clear(); $cost = 0
        }
        $group.Add($t.Text); $cost += $t.Cost
    }
    if ($group.Count -gt 0) { $selects.Add("      <Select Path=`"$Path`">*[System[($($group -join ' or '))]]</Select>") }
    return $selects
}

# Suppress rules: optional, from the settings table, applied per channel.
$suppressRules = @()
if (Get-Variable -Name BaselineWefSuppress -Scope Script -ErrorAction SilentlyContinue) { $suppressRules = @($script:BaselineWefSuppress) }

$queryParts = New-Object System.Collections.Generic.List[string]
$queryId = 0
foreach ($chName in $channels) {
    $esc = ConvertTo-XmlEscaped $chName
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("    <Query Id=`"$queryId`" Path=`"$esc`">")
    if ($Filter -eq 'Baseline' -and $chName -eq 'Security') {
        $lines.Add("      <!-- Security: $($securityIds.Count) event IDs from $($subcategoryGuids.Count) enabled audit subcategories + Eventlog service events -->")
        foreach ($s in (ConvertTo-EventIdSelectXml -Ids $securityIds -Path $esc -MaxExpressions $maxExpressionsPerSelect)) { $lines.Add($s) }
    } else {
        $lines.Add("      <Select Path=`"$esc`">*</Select>")
    }
    foreach ($rule in $suppressRules) {
        if ($rule.Channel -ne $chName) { continue }
        $lines.Add("      <!-- Suppress: $(($rule.Reason -replace '--', '- -')) -->")
        $lines.Add("      <Suppress Path=`"$esc`">$($rule.XPath)</Suppress>")
    }
    $lines.Add('    </Query>')
    $queryParts.Add(($lines -join "`r`n"))
    $queryId++
}
$queryList = "<QueryList>`r`n" + ($queryParts -join "`r`n") + "`r`n  </QueryList>"

$readExisting = 'false'
if ($ReadExistingEvents) { $readExisting = 'true' }

$subIdEsc = ConvertTo-XmlEscaped $SubscriptionId
$sddlEsc  = ConvertTo-XmlEscaped $AllowedSourceDomainComputersSddl
$descEsc  = ConvertTo-XmlEscaped "WinLogKit logging baseline forwarding ($sourceDesc, $Filter filter)"
# XML comments must not contain '--'; neutralise any from user-supplied names.
$commentDesc = ($sourceDesc -replace '--', '- -')
$modeComment = if ($Filter -eq 'Baseline') { "Baseline filter: Security limited to $($securityIds.Count) documented event IDs of the enabled subcategories; other channels whole." } else { 'Channel filter: every event of each selected channel.' }

$xml = @"
<!-- Generated by WinLogKit New-WefSubscription.ps1 from $commentDesc ($($channels.Count) channels). -->
<!-- $modeComment Regenerate from the kit rather than editing by hand; verify on the collector with Test-WefFilter.ps1. -->
<Subscription xmlns="http://schemas.microsoft.com/2006/03/windows/events/subscription">
  <SubscriptionId>$subIdEsc</SubscriptionId>
  <SubscriptionType>SourceInitiated</SubscriptionType>
  <Description>$descEsc</Description>
  <Enabled>true</Enabled>
  <Uri>http://schemas.microsoft.com/wbem/wsman/1/windows/EventLog</Uri> <!-- DevSkim: ignore DS137138 - fixed WS-Eventing protocol identifier, not a network endpoint -->
  <ConfigurationMode>Custom</ConfigurationMode>
  <Delivery Mode="Push">
    <Batching>
      <MaxItems>$MaxItems</MaxItems>
      <MaxLatencyTime>$($MaxLatencySeconds * 1000)</MaxLatencyTime>
    </Batching>
    <PushSettings>
      <Heartbeat Interval="$($HeartbeatSeconds * 1000)" />
    </PushSettings>
  </Delivery>
  <Query><![CDATA[$queryList]]></Query>
  <ReadExistingEvents>$readExisting</ReadExistingEvents>
  <TransportName>HTTP</TransportName>
  <ContentFormat>$ContentFormat</ContentFormat>
  <Locale Language="en-US" />
  <LogFile>ForwardedEvents</LogFile>
  <AllowedSourceNonDomainComputers></AllowedSourceNonDomainComputers>
  <AllowedSourceDomainComputers>$sddlEsc</AllowedSourceDomainComputers>
</Subscription>
"@

# ---------------------------------------------------------------- validate ---

$validationFailed = $false
if ($Validate) {
    Write-Host 'Validating each query against this machine''s event log engine...' -ForegroundColor White
    foreach ($part in $queryParts) {
        $single = "<QueryList>`r`n$part`r`n</QueryList>"
        $chName = [regex]::Match($part, 'Path="([^"]+)"').Groups[1].Value
        try {
            Get-WinEvent -FilterXml ([xml]$single) -MaxEvents 1 -ErrorAction Stop | Out-Null
            Write-Host "  OK        $chName (query parses; events present)"
        } catch {
            $msg = $_.Exception.Message
            if ($msg -match 'No events were found') {
                Write-Host "  OK        $chName (query parses; no matching events on this host)"
            } elseif ($msg -match 'Attempted to perform an unauthorized operation|access is denied|There is not an event log|does not exist|could not be found|not found') {
                # Needs admin (Security, SMB audit logs) or the channel is absent here (PowerShellCore without PS7): syntax cannot be judged, so not a failure.
                Write-Host "  UNCHECKED $chName ($msg)" -ForegroundColor Yellow
            } else {
                Write-Host "  INVALID   $chName : $msg" -ForegroundColor Red
                $validationFailed = $true
            }
        }
    }
    if ($validationFailed) { Write-Error 'One or more queries are not valid event XPath. Nothing written.'; exit 1 }
}

# ------------------------------------------------------------------- write ---

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outDirFull = (Resolve-Path $OutDir).Path
$outFile = Join-Path $outDirFull "$SubscriptionId.xml"
$sidecar = Join-Path $outDirFull "$SubscriptionId.expected-eventids.csv"
$utf8 = New-Object System.Text.UTF8Encoding($false)
# UTF-8 without BOM, consistent with the Intune pack outputs.
[System.IO.File]::WriteAllText($outFile, $xml, $utf8)

$sideRows = New-Object System.Collections.Generic.List[string]
$sideRows.Add('Channel,EventID')
foreach ($chName in $expected.Keys) {
    foreach ($id in $expected[$chName]) { $sideRows.Add(('"{0}",{1}' -f ($chName -replace '"', '""'), $id)) }
}
[System.IO.File]::WriteAllText($sidecar, (($sideRows -join "`n") + "`n"), $utf8)

# ------------------------------------------------------------------ output ---

Write-Host "WEF subscription written: $outFile ($($channels.Count) channels, $Filter filter, from $sourceDesc)" -ForegroundColor Green
Write-Host "Expected-delivery sidecar: $sidecar (feed it to Test-WefFilter.ps1 on the collector)"
if ($Filter -eq 'Baseline') {
    Write-Host ''
    Write-Host "Security channel filtered to $($securityIds.Count) event IDs from:" -ForegroundColor White
    foreach ($l in $coverageLines) { Write-Host $l }
    Write-Host '  Every other selected channel is forwarded whole.'
}
if ($suppressRules.Count -gt 0) { Write-Host "Suppress rules applied: $($suppressRules.Count) (from `$BaselineWefSuppress)" }
Write-Host ''
Write-Host 'Collector setup (domain-joined server):' -ForegroundColor White
Write-Host '  winrm qc -q          # WinRM listener first - sources connect to it'
Write-Host '  wecutil qc /q        # then the Windows Event Collector service'
Write-Host "  wecutil cs `"$outFile`""
Write-Host '  Size ForwardedEvents like any busy log:  wevtutil sl ForwardedEvents /ms:1073741824'
Write-Host ''
Write-Host 'Source setup (via GPO):' -ForegroundColor White
Write-Host '  Computer Configuration > Administrative Templates > Windows Components > Event Forwarding'
Write-Host '  > Configure target Subscription Manager:'
Write-Host "    Server=http://<collector-fqdn>:5985/wsman/SubscriptionManager/WEC,Refresh=$($wefDefaults.SubscriptionRefreshSeconds)"  # DevSkim: ignore DS137138 - documented WinRM default; WEF payloads are Kerberos message-level encrypted over HTTP
Write-Host '    (optionally HTTPS: Server=https://<collector-fqdn>:5986/... - needs a server certificate on the collector)'
Write-Host '  For the Security log: add NETWORK SERVICE to "Event Log Readers" on sources, or Security forwarding silently fails.' -ForegroundColor Yellow
Write-Host ''
Write-Host "Prove the filter on the collector:  .\Test-WefFilter.ps1 -ExpectedFile `"$sidecar`" -SubscriptionId $SubscriptionId"
Write-Host 'SIEM handoff point: the ForwardedEvents log on the collector. Ingestion beyond that is out of kit scope.'
exit 0
