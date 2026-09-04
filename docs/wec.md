# Collect

Central collection with Windows Event Forwarding (WEF): generate the
subscription from the same selection you applied, set up the collector and
the sources, read what an existing collector is already doing, and prove
that events arrive. The commands under "Set up" change collector and source configuration;
everything else only reads it (two commands write export files to the
current folder), so it is safe on a production collector.

Where this sits in the chain:

```text
Source host                       WEC collector                      SIEM
[audit policy + channels] --push--> [subscription -> ForwardedEvents] --agent--> [your platform]
        Gate 1                            Gate 2                        Gate 3
```

The gates multiply. An event reaches the collector only if it is
**generated** on the source (Gate 1, the baseline's job) *and* **matched**
by the subscription query (Gate 2, this page). A subscription cannot forward
what was never generated, and source config cannot force forwarding of a
channel the subscription does not name. Keeping both generated from the
same baseline selection is why
[`New-WefSubscription.ps1`](commands.md#new-wefsubscriptionps1) exists.
Gate 3, the hop from ForwardedEvents into a SIEM, is deliberately outside
the kit: any agent or connector that reads a Windows event log will do. One
worked example for Microsoft Sentinel is kept as an
[extra](extras/sentinel-kql.md).

## Generate the subscription

```powershell
.\fleet\New-WefSubscription.ps1 [-BaselineFile <csv>] [-Filter Channel|Baseline] [-Validate] [-SubscriptionId <name>]
```

Generates a source-initiated subscription XML with one query per selected
channel, plus a sidecar `<name>.expected-eventids.csv` saying what it
should deliver. Transport defaults (`Events` format, 30s/500-item batching,
1h heartbeat, source SDDL) live in the settings table and are overridable
per run.

Two filter modes. `-Filter Channel` (default) forwards every event of each
selected channel: the baseline's channel selection is the coarse filter and
the right first deployment. `-Filter Baseline` narrows the Security channel
to exactly the event IDs the baseline's enabled audit subcategories can
produce, plus the always-on log-tamper events, and leaves every other
channel whole; see
[filtering with XPath](#filtering-with-xpath-matching-the-subscription-to-the-baseline)
below. Add `-Validate` to parse each query in the local event engine before
deploying, then prove the filter on the collector with
`Test-WefFilter.ps1`.

## Set up the collector and the sources

The generator prints the full setup; the essentials:

```text
Collector:  winrm qc -q            (WinRM listener first)
            wecutil qc /q          (then the collector service)
            wecutil cs .\WEF\WinLogKit-Baseline.xml
            wevtutil sl ForwardedEvents /ms:1073741824
Sources:    winrm qc -q   (WinRM must be configured on each source too - or
                           enable the WinRM service via GPO fleet-wide)
            GPO > Event Forwarding > Configure target Subscription Manager
            Server=http://<collector-fqdn>:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

Per [Microsoft's source-initiated subscription procedure](https://learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription),
both ends need WinRM: the collector to listen, the sources to forward.

The classic trap: for the Security log, add NETWORK SERVICE to **Event Log
Readers** on sources, or Security forwarding silently fails. Verify either
side with:

```powershell
.\Test-LoggingBaseline.ps1 -WefRole Source      # forwarding host: SubscriptionManager policy present, WinRM state
.\Test-LoggingBaseline.ps1 -WefRole Collector   # collector: Wecsvc, ForwardedEvents sizing, a subscription loaded
```

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
| `<LogFile>` | Where events land on the collector, normally `ForwardedEvents`. This page assumes `ForwardedEvents`; if a subscription writes to another log, substitute that channel in every downstream step (sizing, agent configuration) |
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
kit's generator emits by default (`-Filter Channel`). Two structural facts:

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

## Filtering with XPath: matching the subscription to the baseline

Whole-channel forwarding is complete but blunt. The next step is a query
that forwards only what the baseline meant to generate - and the place to
do it is the subscription, because of one fact about how WEF works:

**The subscription's XPath is evaluated on each source.** In a
[source-initiated subscription](https://learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription)
the collector hands the subscription, query included, to every source, and
each source's forwarding service sends only the events that match, before
anything leaves the machine. An event dropped here never reaches the
network, the collector or the SIEM; any SIEM-side transform runs after
forwarding, so the subscription is the earliest filter in the chain.

### The XPath subset

Windows Event Log accepts a
[subset of XPath 1.0](https://learn.microsoft.com/windows/win32/wes/consuming-events)
over the event's XML. In practice a subscription needs three shapes:

| Shape | Example | Meaning |
|---|---|---|
| Whole channel | `*` | every event |
| By event ID | `*[System[(EventID=4688 or (EventID >= 4720 and EventID <= 4726))]]` | the listed IDs and ranges |
| By event data | `*[EventData[Data[@Name="TargetUserName"]="svc-backup"]]` | field-level match |

Two rules shape how queries are written. **Suppress beats Select**: an
event matching any `<Suppress>` is dropped even if a `<Select>` wants it.
And each `<Select>` or `<Suppress>` is
[limited to 32 expressions](https://learn.microsoft.com/windows/win32/wes/queryschema-querytype-complextype),
where `EventID=N` costs one and a range `(EventID >= a and EventID <= b)`
costs two - so long ID lists are split across several `<Select>` elements
in the same `<Query>`, and consecutive IDs are collapsed into ranges.
Inside the subscription XML the query sits in CDATA, but the query is
itself XML: write `<=` as `&lt;=`.

### Matching the filter to the baseline

The baseline selects *audit subcategories*; each subcategory produces a
fixed, Microsoft-documented set of Security event IDs. That makes the
Security filter derivable rather than hand-written:

```text
baseline CSV  ->  enabled subcategory GUIDs
              ->  union of their documented event IDs   (data\wef\audit_subcategory_events.csv)
              +   the always-on Eventlog-service events  (1100, 1102, 1104, 1105, 1108)
              ->  <Select Path="Security"> elements, ranges collapsed, 20 expressions each
```

`New-WefSubscription.ps1 -Filter Baseline -BaselineFile <csv>` does exactly
that; every other channel stays `*`, because the baseline enables those
channels as units. The generated `<Query>` for a full server preset looks
like:

```xml
<Query Id="0" Path="Security">
  <!-- Security: 262 event IDs from 33 enabled audit subcategories + Eventlog service events -->
  <Select Path="Security">*[System[(EventID=1100 or EventID=1102 or (EventID >= 1104 and EventID &lt;= 1105) or EventID=1108 or (EventID >= 4608 and EventID &lt;= 4612) ... )]]</Select>
  <Select Path="Security">*[System[((EventID >= 4661 and EventID &lt;= 4663) or (EventID >= 4670 and EventID &lt;= 4675) or EventID=4688 ... )]]</Select>
  ...
</Query>
```

Why the *complete* documented set and not a curated "interesting events"
list: the two gates must agree. If the baseline enables a subcategory, the
filter must forward everything that subcategory can produce, or it silently
drops events someone decided to generate. The table below is the whole
contract:

| Baseline (Gate 1) | Filter (Gate 2) | Result |
|---|---|---|
| Subcategory enabled | Its IDs selected | Forwarded - the intended case |
| Subcategory enabled | Not selected | Cannot happen: the filter is derived from the same selection |
| Subcategory not enabled | Its IDs not selected | Never generated, nothing to filter |
| Event outside any enabled subcategory | Not selected | Generated by something else, stays local |

The event map is a vendored snapshot with the source URL on every row
(`data\wef\README.md`); the kit refuses to build a Baseline filter for a
subcategory it has no documented IDs for, rather than drop them.

**Suppress** is the other half, and it is a policy decision, not a tuning
knob: anything suppressed never reaches the collector, the SIEM, or any
retention. The kit ships no suppress rules; `$BaselineWefSuppress` in the
settings table is where measured, defensible noise rules go (channel,
XPath, reason), and the generator writes them into the query with the
reason as a comment.

### Confirming it works

Four checks, cheapest first:

1. **Does it parse?** `New-WefSubscription.ps1 ... -Validate` runs every
   generated query through the local event engine (`Get-WinEvent
   -FilterXml`). A bad expression fails the run before anything is
   written; "no events found" and "access denied" mean the syntax is fine.
2. **Is it the deployed query?** On the collector, `wecutil gs <name>
   /f:xml` shows the registered `<Query>`; `Test-WefFilter.ps1
   -SubscriptionId <name>` compares it to the generated file, so a hand
   edit or a stale registration shows up.
3. **Is it in effect?** `Test-WefFilter.ps1 -ExpectedFile
   <name>.expected-eventids.csv` reads ForwardedEvents and lists every
   Security event ID that arrived but is not in the expected set. Any
   UNEXPECTED row means the filter is not applied (or another subscription
   forwards more). Expected-but-unseen IDs are informational: the sources
   may simply not have produced them in the window.
4. **Same check at the SIEM end.** The script prints the KQL: `WindowsEvent
   | where Channel == "Security" | where EventID !in (...)` - any row
   returned is an event the filter should have stopped.

What the filter buys you is measurable before and after: the Security
channel's share of ingested volume per source is the number to compare
(the [Sentinel extra](extras/sentinel-kql.md#query-pack) has the queries).
