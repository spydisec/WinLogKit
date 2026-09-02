# WEC Collector

A practical guide to the Windows Event Collector side of central
collection: reading what a collector is already doing, understanding the
subscription that controls it, and verifying that sources are actually
sending. Everything here is read-only unless marked otherwise, so it is
safe on a production collector.

Where this sits in the chain:

```text
Member server                     WEC collector                      SIEM
[audit policy + channels] --push--> [subscription -> ForwardedEvents] --agent--> [workspace]
        Gate 1                            Gate 2                        Gate 3
```

The gates multiply. An event reaches the collector only if it is
**generated** on the source (Gate 1, this kit's job) *and* **matched** by
the subscription query (Gate 2, this page). A subscription cannot forward
what was never generated, and source config cannot force forwarding of a
channel the subscription does not name. Keeping both generated from the
same baseline selection is why
[`New-WefSubscription.ps1`](commands.md#new-wefsubscriptionps1) exists.
Gate 3 is covered on the [Sentinel KQL](kql.md) page.

## There is no default subscription

A Windows box ships with zero subscriptions; the Windows Event Collector
service is not even configured until `wecutil qc` runs. Whatever exists on
a collector today was put there by someone. Reading it back is the first
step of any assessment:

```powershell
wecutil es                          # enumerate all subscription names
wecutil gs "<SubName>" /f:xml       # full configuration as XML
wecutil gr "<SubName>"              # runtime status: sources, state, heartbeats
```

Evidence-grade export of everything in one go:

```powershell
wecutil es | ForEach-Object { wecutil gs $_ /f:xml | Out-File ".\WEF-Sub-$($_ -replace '[\\/:*?\"<>|]','_').xml" }
```

The same information is in Event Viewer under **Subscriptions**, but the
XML is what you keep. Command reference:
[wecutil](https://learn.microsoft.com/windows-server/administration/windows-commands/wecutil).

## Reading a subscription: the fields that matter

| Field in the XML | What it controls |
|---|---|
| `<SubscriptionType>` | `SourceInitiated` (sources push to the collector over WinRM, the model that scales) or `CollectorInitiated` (the collector pulls; account-heavy, usually legacy) |
| `<Query>` | The authoritative "what is forwarded" filter - one `<Select Path="channel">` per channel |
| `<AllowedSourceDomainComputers>` | SDDL naming which computers may participate (normally an AD group) - the "who sends" control |
| `<LogFile>` | Where events land on the collector, normally `ForwardedEvents`. This guide and the [Sentinel KQL](kql.md) page assume `ForwardedEvents`; if a subscription writes to another log, substitute that channel in every downstream step (sizing, DCR XPath) |
| `<ConfigurationMode>` | The delivery/latency trade-off (table below) |
| `<ContentFormat>` | `Events` (compact, recommended) or `RenderedText` (adds locale-rendered strings, inflates volume) |
| `<ReadExistingEvents>` | Whether a newly joined source backfills existing events or starts from now |

Delivery modes set the latency floor for everything downstream - no SIEM
query can see an event before the source has batched and sent it. The
values below are the documented approximate defaults (per the
[wecutil reference](https://learn.microsoft.com/windows-server/administration/windows-commands/wecutil));
treat them as order-of-magnitude, not guarantees:

| ConfigurationMode | Batching behaviour (approximate defaults) |
|---|---|
| `MinLatency` | ~30 seconds |
| `Normal` | batched delivery, up to ~15 minutes |
| `MinBandwidth` | up to ~6 hours |
| `Custom` | Whatever `<Delivery>` specifies |

## "Wide open" queries

A subscription must contain a query, but the query can be per-channel
wildcards with no event-level filtering:

```xml
<Query Id="0">
  <Select Path="Security">*</Select>
  <Select Path="Microsoft-Windows-PowerShell/Operational">*</Select>
  <Select Path="Microsoft-Windows-TaskScheduler/Operational">*</Select>
</Query>
```

`*` means every event in that channel - as open as WEF gets, and what this
kit's generator emits. Two structural facts:

- There is **no channel wildcard**. "All channels on the machine" cannot be
  expressed; every channel must be listed as its own `Select`. Windows
  [limits a query to 32 expressions](https://learn.microsoft.com/windows/win32/wes/queryschema-querytype-complextype)
  (`Select`/`Suppress` combined), so a channel list beyond that needs
  additional `<Query>` elements or subscriptions.
- Whole-channel forwarding makes the **source configuration the effective
  filter**, which is easy to verify ("every event in channels X, Y, Z
  present on a source = forwarded") but means volume is governed entirely
  upstream. Starting wide open and tightening with evidence after a pilot
  is a defensible sequence; Microsoft's
  [WEF intrusion-detection guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
  has curated per-event queries to graduate to.

## Who sends: two lists that must agree

With source-initiated WEF, a machine forwards only if **both** hold:

1. It received the **SubscriptionManager** policy pointing at this
   collector (GPO: Computer Configuration > Policies > Administrative
   Templates > Windows Components > Event Forwarding). On a source, the
   applied value is readable at
   `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager`.
2. Its computer account is inside the subscription's
   `<AllowedSourceDomainComputers>` SDDL.

When these are scoped by two different AD groups they drift independently -
worth a standing check.

## Runtime status: the reconciliation

`wecutil gr "<SubName>"` lists every registered source with its state and
last heartbeat. The health assertion worth writing down as an acceptance
criterion is a three-way count:

> AD group membership = registered sources = sources in state Active.

Machines in the group but never registered have a broken hop (GPO not
applied, WinRM unreachable, or the Security-log permission below) - but
first allow the SubscriptionManager refresh interval to elapse, since a
source does not appear until it has checked in.
Machines registered but Inactive have not met the subscription's activity
and heartbeat criteria - the cause can be connectivity, authentication or
simply nothing to send, so investigate rather than assume. Name the
discrepancies; do not just record the counts.

## ForwardedEvents channel health

```powershell
wevtutil gl ForwardedEvents
Get-WinEvent -ListLog ForwardedEvents | Select-Object RecordCount, FileSize, IsLogFull, LastWriteTime
```

- **Size it like a busy log.** All forwarded volume concentrates here.
- **Retention must stay circular** (overwrite as needed). "Do not
  overwrite" silently stops collection when full - the same trap
  [Test-LoggingBaseline flags](safety.md#what-the-kit-will-never-do) on
  any channel.
- **Know the headroom**: at the observed events/hour, how many hours does
  the channel hold? That is the buffer available if the onward SIEM hop
  goes down.

## Classic silent failures

| Symptom | Cause |
|---|---|
| Every channel forwards except Security, no loud error anywhere | NETWORK SERVICE cannot read the Security log on the source. Fix: add it to the **Event Log Readers** group, or grant read via the channel's SDDL where group membership alone is not honoured (both per [Microsoft's WEF guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)). |
| Sources registered, zero events arriving | Gate 1: the subscribed channels are not enabled/generating on the sources - verify with [`Test-LoggingBaseline.ps1`](commands.md#test-loggingbaselineps1) |
| Some machines never register | SubscriptionManager GPO scope vs `AllowedSourceDomainComputers` mismatch, or WinRM (5985/5986) blocked |
| Collection stops after working fine | ForwardedEvents full with non-circular retention |
| Volume far above estimate | `RenderedText` content format, or a high-volume source-side setting (see the [volume table](safety.md#volume-impact-settings-the-highvolume-tier-and-friends)) |

## Verifying from this kit

- `Test-LoggingBaseline.ps1 -WefRole Source` - is this machine configured
  to forward (SubscriptionManager present, WinRM service state)?
- `Test-LoggingBaseline.ps1 -WefRole Collector` - is this machine
  configured to collect?
- `New-WefSubscription.ps1 -BaselineFile <csv>` - generate a subscription
  whose channel list is provably identical to what the sources enable, so
  Gates 1 and 2 cannot drift apart.

Onward: [Sentinel KQL](kql.md) covers Gate 3 - confirming the collector's
agent ships ForwardedEvents to a workspace, and the queries that prove the
whole chain end-to-end.
