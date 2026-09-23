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

    Every event of each selected channel is forwarded:
    <Select Path="Security">*</Select>. The baseline's channel selection is
    the filter. To cut volume further, filter at your SIEM's ingest layer,
    where a mistake can be seen and undone. (v1's -Filter Baseline, which
    narrowed Security to documented event IDs at the source, was removed in
    v2: it failed silently when wrong - ADR-002, as were Suppress rules.)

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
    in WinLogKit.Settings.ps1 ($BaselineWefDefaults); parameters here
    override them per run.

    Generation is read-only: no admin needed, nothing on the host changes.

.PARAMETER BaselineFile
    Optional selection CSV from New-LoggingBaseline.ps1. Selected = Y channel
    rows are forwarded. Without it, the kit's Core tier is used (plus
    HighVolume items if -IncludeHighVolume is given).

.PARAMETER Filter
    Kept for v1 command lines: 'Channel' is the only mode and is accepted
    silently; 'Baseline' was removed in v2 and stops the run with a pointer
    to the migration note.

.PARAMETER Validate
    Parse every generated query with this machine's event log engine.

.PARAMETER SubscriptionId
    Subscription name shown in wecutil / Event Viewer. Default: WinLogKit-Baseline.

.PARAMETER OutDir
    Where the XML is written. Default: WEF\ at the kit root (the parent of fleet\).

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
    .\fleet\New-WefSubscription.ps1
    Core-tier channels into .\WEF\WinLogKit-Baseline.xml.

.EXAMPLE
    .\fleet\New-WefSubscription.ps1 -BaselineFile .\presets\MemberServer.csv -Validate
    The channels that preset selects; every query parsed locally.
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
# This script lives in fleet\; the settings table, shared helpers, data
# and output folders are at the kit root.
$kitRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrEmpty($OutDir)) { $OutDir = Join-Path $kitRoot 'WEF' }

if ($Filter -eq 'Baseline') {
    Write-Error '-Filter Baseline was removed in v2 (ADR-002): the subscription forwards whole channels. Filter at your SIEM ingest layer instead; see the v2.0.0 CHANGELOG entry.'
    exit 1
}

. (Join-Path $kitRoot 'WinLogKit.Settings.ps1')
. (Join-Path $kitRoot 'WinLogKit.Common.ps1')

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

# ------------------------------------------------------ selection (what) ---

$channels = New-Object System.Collections.Generic.List[string]
$sel = Resolve-BaselineSelection -BaselineFile $BaselineFile -IncludeHighVolume $IncludeHighVolume -IncludeOptional $IncludeOptional
foreach ($ch in $script:BaselineChannels) {
    if (Test-ItemSelected $sel 'Channel' $ch.Name $ch.Tier) { $channels.Add($ch.Name) }
}
$sourceDesc = $sel.Description

if ($channels.Count -eq 0) {
    Write-Error 'No channels selected - nothing to forward.'
    exit 1
}

# --------------------------------------------------------------- build XML ---

function ConvertTo-XmlEscaped { param([string]$s) [System.Security.SecurityElement]::Escape($s) }

$queryParts = New-Object System.Collections.Generic.List[string]
$queryId = 0
foreach ($chName in $channels) {
    $esc = ConvertTo-XmlEscaped $chName
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("    <Query Id=`"$queryId`" Path=`"$esc`">")
    $lines.Add("      <Select Path=`"$esc`">*</Select>")
    $lines.Add('    </Query>')
    $queryParts.Add(($lines -join "`r`n"))
    $queryId++
}
$queryList = "<QueryList>`r`n" + ($queryParts -join "`r`n") + "`r`n  </QueryList>"

$readExisting = 'false'
if ($ReadExistingEvents) { $readExisting = 'true' }

$subIdEsc = ConvertTo-XmlEscaped $SubscriptionId
$sddlEsc  = ConvertTo-XmlEscaped $AllowedSourceDomainComputersSddl
$descEsc  = ConvertTo-XmlEscaped "WinLogKit logging baseline forwarding ($sourceDesc)"
# XML comments must not contain '--'; neutralise any from user-supplied names.
$commentDesc = ($sourceDesc -replace '--', '- -')

$xml = @"
<!-- Generated by WinLogKit New-WefSubscription.ps1 from $commentDesc ($($channels.Count) channels). -->
<!-- Every event of each selected channel is forwarded. Regenerate from the kit rather than editing by hand. -->
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
            # Classify on the stable error identifier, not the (localised)
            # message text. Observed identifiers from Get-WinEvent:
            #   NoMatchingEventsFound            valid query, nothing matched -> OK
            #   NoMatchingLogsFound              channel absent on this host  -> UNCHECKED
            #   System.UnauthorizedAccessException  cannot read the channel   -> UNCHECKED
            #   ...EventLogException             the query itself is bad      -> INVALID
            $fqid = "$($_.FullyQualifiedErrorId)"
            $msg  = $_.Exception.Message
            if ($fqid -match 'NoMatchingEventsFound') {
                Write-Host "  OK        $chName (query parses; no matching events on this host)"
            } elseif ($fqid -match 'NoMatchingLogsFound|UnauthorizedAccessException') {
                # Needs admin (Security, SMB audit logs) or the channel is absent here (PowerShellCore without PS7): syntax cannot be judged, so not a failure.
                Write-Host "  UNCHECKED $chName ($msg)" -ForegroundColor Yellow
            } else {
                Write-Host "  INVALID   $chName : $msg [$fqid]" -ForegroundColor Red
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
# UTF-8 without BOM, consistent with the other generated artefacts.
[System.IO.File]::WriteAllText($outFile, $xml, (New-Object System.Text.UTF8Encoding($false)))

# ------------------------------------------------------------------ output ---

Write-Host "WEF subscription written: $outFile ($($channels.Count) channels, from $sourceDesc)" -ForegroundColor Green
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
Write-Host "Verify: on the collector, Test-LoggingBaseline.ps1 -WefRole Collector; on a source, -WefRole Source."
Write-Host 'SIEM handoff point: the ForwardedEvents log on the collector. Ingestion beyond that is out of kit scope.'
exit 0
