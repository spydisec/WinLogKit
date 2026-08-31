<#
.SYNOPSIS
    Generates a source-initiated Windows Event Forwarding (WEF) subscription
    XML from the kit's settings table (or a baseline selection CSV), so the
    channels this kit enables can be collected centrally on a Windows Event
    Collector (WEC) - agentless, native, no third party components.

.DESCRIPTION
    Where this sits in the pipeline: the kit makes hosts PRODUCE the right
    events (generate); WEF/WEC moves selected events to a collector's
    ForwardedEvents log (transport); your SIEM picks them up from the
    collector (ingest - out of scope for this kit by design).

    The generated subscription forwards ALL events from each selected channel.
    That is deliberate for a first deployment: channel selection (via your
    baseline CSV) is the coarse filter, and per-event XPath tuning is an
    operator decision made after observing volume - see Microsoft's WEF
    intrusion-detection guidance for curated event queries:
    https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection

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
    Optional selection CSV from New-LoggingBaseline.ps1. Only Selected = Y
    channel rows are forwarded. Without it, the kit's Core tier channels are
    used (plus HighVolume/Optional channels if the matching switch is given).

.PARAMETER SubscriptionId
    Subscription name shown in wecutil / Event Viewer. Default: WinLogKit-Baseline.

.PARAMETER OutDir
    Where the XML is written. Default: .\WEF next to this script.

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
    Core-tier channels into .\WEF\WinLogKit-Baseline.xml.

.EXAMPLE
    .\New-WefSubscription.ps1 -BaselineFile .\presets\ASD.csv -SubscriptionId ASD-Baseline
    Subscription covering exactly the channels the ASD preset selects.
#>
[CmdletBinding()]
param(
    [string]$BaselineFile,
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

# ---------------------------------------------------------- channel choice ---

$channels = New-Object System.Collections.Generic.List[string]

if (-not [string]::IsNullOrEmpty($BaselineFile)) {
    if (-not (Test-Path $BaselineFile)) {
        Write-Error "Baseline file not found: $BaselineFile (build one with New-LoggingBaseline.ps1 or use a preset)"
        exit 1
    }
    foreach ($row in (Import-Csv $BaselineFile)) {
        if ($row.ItemType -eq 'Channel' -and ("$($row.Selected)".Trim() -match '^(Y|YES|TRUE|1)$')) {
            $channels.Add($row.Id)
        }
    }
    $sourceDesc = "baseline file $(Split-Path $BaselineFile -Leaf)"
} else {
    foreach ($ch in $script:BaselineChannels) {
        $take = ($ch.Tier -eq 'Core')
        if ($ch.Tier -eq 'HighVolume' -and $IncludeHighVolume) { $take = $true }
        if ($ch.Tier -eq 'Optional' -and $IncludeOptional) { $take = $true }
        if ($take) { $channels.Add($ch.Name) }
    }
    $sourceDesc = "kit Core tier$(if ($IncludeHighVolume) {' + HighVolume'})$(if ($IncludeOptional) {' + Optional'})"
}

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
    $queryParts.Add("    <Query Id=`"$queryId`" Path=`"$esc`"><Select Path=`"$esc`">*</Select></Query>")
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
<!-- Regenerate from the kit rather than editing by hand. Channel-level forwarding: tune per-event XPath after observing volume. -->
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

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$outFile = Join-Path $OutDir "$SubscriptionId.xml"
# UTF-8 without BOM, consistent with the Intune pack outputs.
[System.IO.File]::WriteAllText((Join-Path (Resolve-Path $OutDir).Path "$SubscriptionId.xml"), $xml, (New-Object System.Text.UTF8Encoding($false)))

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
Write-Host '    Server=http://<collector-fqdn>:5985/wsman/SubscriptionManager/WEC,Refresh=60'  # DevSkim: ignore DS137138 - documented WinRM default; WEF payloads are Kerberos message-level encrypted over HTTP
Write-Host '    (optionally HTTPS: Server=https://<collector-fqdn>:5986/... - needs a server certificate on the collector)'
Write-Host '  For the Security log: add NETWORK SERVICE to "Event Log Readers" on sources, or Security forwarding silently fails.' -ForegroundColor Yellow
Write-Host ''
Write-Host 'SIEM handoff point: the ForwardedEvents log on the collector. Ingestion beyond that is out of kit scope.'
exit 0
