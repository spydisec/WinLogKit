# Collect

Send the events your baseline turns on to one central server with Windows
Event Forwarding (WEF), the collection method built into Windows. No agent
is installed on the sources.

```text
Source host                       Collector (WEC)                    SIEM
[audit policy + channels] --push--> [subscription -> ForwardedEvents] --agent--> [your platform]
     1. generated                      2. forwarded                    3. ingested
```

An event reaches the collector only if it is **generated** on the source
(the baseline's job) *and* **forwarded** by the subscription (this page).
Generating the subscription from the same baseline CSV keeps the two in
step. Step 3, getting events from the collector into your SIEM, is outside
the kit: any agent or connector that reads a Windows event log works.

## 1. Generate the subscription

```powershell
.\fleet\New-WefSubscription.ps1 -BaselineFile .\presets\MemberServer.csv -Validate
```

This writes `.\WEF\WinLogKit-Baseline.xml`, a source-initiated subscription
that forwards every event of each channel the baseline selects.
`-Validate` checks each query against this machine's event log engine
first. Batching, heartbeat and the format live in the settings table and
can be overridden per run (see [Commands](commands.md#new-wefsubscriptionps1)).

## 2. Set up the collector and the sources

The script prints these steps too:

```text
Collector:  winrm qc -q            (WinRM listener first)
            wecutil qc /q          (then the collector service)
            wecutil cs .\WEF\WinLogKit-Baseline.xml
            wevtutil sl ForwardedEvents /ms:1073741824
Sources:    winrm qc -q            (or enable WinRM fleet-wide by GPO)
            GPO > Event Forwarding > Configure target Subscription Manager:
            Server=http://<collector-fqdn>:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

Both ends need WinRM, per
[Microsoft's source-initiated subscription procedure](https://learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription).

!!! warning "The classic trap"
    For the Security log, add NETWORK SERVICE to the **Event Log Readers**
    group on every source. Without it, every other channel forwards and
    Security silently doesn't.

## 3. Verify

```powershell
.\Test-LoggingBaseline.ps1 -WefRole Source      # on a source: forwarding policy set, WinRM running
.\Test-LoggingBaseline.ps1 -WefRole Collector   # on the collector: service, ForwardedEvents size, a subscription loaded
```

On the collector, `wecutil gr WinLogKit-Baseline` lists every source that
has registered, with its state and last heartbeat.

## When events don't arrive

| Symptom | Cause |
|---|---|
| Every channel forwards except Security | NETWORK SERVICE can't read the Security log on the source: add it to **Event Log Readers** (or grant read in the channel's SDDL), per [Microsoft's WEF guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection) |
| Sources registered, no events | The channels aren't enabled or generating on the sources: run [`Test-LoggingBaseline.ps1`](commands.md#test-loggingbaselineps1) there |
| Some machines never register | The Subscription Manager GPO and the subscription's allowed-computers list cover different machines, or WinRM (5985/5986) is blocked. Allow for the refresh interval before judging |
| Collection stops after working fine | ForwardedEvents is full and set to "do not overwrite"; it must be circular |
| Far more volume than expected | `RenderedText` content format, or a HighVolume setting (see the [volume table](safety.md#volume-impact-settings-the-highvolume-tier-and-friends)) |

## Filtering

The kit forwards whole channels and stops there. To cut volume, filter at
your SIEM's ingest layer (for example a Sentinel data collection rule
transform), where a mistake is visible and can be undone. A filter inside
the subscription runs on each source before anything is sent, so a
slightly wrong XPath drops events silently. If you do filter at the source,
start from Microsoft's
[WEF intrusion-detection guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection).

## Checking an existing collector

A Windows server has no subscriptions until someone creates one, so
whatever a collector runs today was put there deliberately. To read it
back:

```powershell
wecutil es                          # list subscription names
wecutil gs "<name>" /f:xml          # full configuration as XML
wecutil gr "<name>"                 # runtime status: sources, state, heartbeats
wevtutil gl ForwardedEvents         # size and retention of the destination log
```

What to look at in the XML
([wecutil reference](https://learn.microsoft.com/windows-server/administration/windows-commands/wecutil)):

| Field | What it tells you |
|---|---|
| `<SubscriptionType>` | `SourceInitiated` (sources push; the model that scales) or `CollectorInitiated` (the collector pulls) |
| `<Query>` | What is forwarded: one `<Select Path="channel">` per channel; `*` means every event in it |
| `<AllowedSourceDomainComputers>` | Which computers may send (normally an AD group) |
| `<LogFile>` | Where events land, normally `ForwardedEvents` |
| `<ConfigurationMode>` | Delivery speed: `MinLatency` about 30 seconds, `Normal` up to about 15 minutes, `MinBandwidth` up to about 6 hours, `Custom` as `<Delivery>` sets |
| `<ContentFormat>` | `Events` (compact) or `RenderedText` (adds message text, larger) |

A healthy collector passes one check: **computers in the allowed AD group =
registered sources = sources in state Active.** Name the machines that
differ rather than just counting them. Size ForwardedEvents like a busy
log, keep it circular, and know how many hours it holds at the current
event rate: that's your buffer if the SIEM connection goes down.
