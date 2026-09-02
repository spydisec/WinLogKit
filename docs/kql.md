# Sentinel KQL

Verifying the last hop: a collector (or any host) shipping events to a Log
Analytics workspace with the Azure Monitor Agent (AMA), and the KQL that
proves the whole chain works. Generic Microsoft Sentinel / Azure Monitor
material - nothing here is specific to this kit, but every query assumes
the [WEC page's](wec.md) architecture: sources push to a collector's
ForwardedEvents log, AMA collects that log.

## Which table the events land in

Forwarded events collected by AMA land in the
[**WindowsEvent**](https://learn.microsoft.com/azure/azure-monitor/reference/tables/windowsevent)
table - that is what the
[Windows Forwarded Events connector](https://learn.microsoft.com/azure/sentinel/data-connectors/windows-forwarded-events)
configures: a
[Data Collection Rule](https://learn.microsoft.com/azure/azure-monitor/agents/data-collection-windows-events)
whose XPath list reads the `ForwardedEvents` channel.

Three things people trip over:

- **`SecurityEvent` is a different table.** The *Windows Security Events
  via AMA* connector reads a machine's **own** Security channel into
  `SecurityEvent`. Pointed at a collector, it ingests the collector's own
  logs - not the forwarded fleet. For WEF you need the DCR reading
  `ForwardedEvents!*`. A detection written only against `SecurityEvent`
  will not see WEF-collected events (ASIM parsers union both tables -
  see [normalisation](https://learn.microsoft.com/azure/sentinel/normalization)).
- **`Computer` is the original source**, not the collector. Forwarded
  events keep the generating machine's name, which is what makes fleet
  verification possible from the workspace end.
- **`Channel` is the original channel** (e.g. `Security`), not
  `ForwardedEvents` - you cannot filter on the transport. The payload sits
  in `EventData` as a dynamic bag (`EventData.CommandLine`), unlike
  `SecurityEvent`'s flattened columns.

## Confirming AMA actually collects ForwardedEvents

Four layers; a green connector page proves none of them individually.

**1. The DCR names the channel:**

```bash
az monitor data-collection rule show --resource-group <rg> --name <dcr> \
  --query "dataSources.windowsEventLogs[].xPathQueries" -o json
```

(Depending on CLI version the payload may nest under `properties` - if the
query returns nothing, retry with
`properties.dataSources.windowsEventLogs[].xPathQueries`. The portal
equivalent is the DCR's **Data sources** blade.)

Look for `ForwardedEvents!*`. Only `Security!*` / `System!*` means the DCR
collects the collector's own logs - the classic looks-healthy failure.

**2. The DCR is associated with the collector:**

```bash
az monitor data-collection rule association list --resource "<collector resource ID>" -o table
```

**3. The agent received that config** (on the collector; AMA caches its
delivered DCRs locally):

```powershell
Get-Service AzureMonitorAgent
Get-ChildItem "C:\WindowsAzure\Resources\AMADataStore.*\mcs\configchunks" -Recurse |
    Select-String -Pattern "ForwardedEvents" -List
```

(Arc-enabled servers cache under `C:\Resources\Directory\AMADataStore`.)
No hit after 10-15 minutes means the delivered config lacks the data
source - the fault can sit in the DCR content, the association, or the
agent's connectivity; work back up the layers. Agent liveness from the
workspace:

```kusto
Heartbeat
| where Computer == "<collector>" and Category == "Azure Monitor Agent"
| summarize max(TimeGenerated)
```

**4. End-to-end tracer.** Generate a known harmless event on a **member
server** (create and delete a test scheduled task = 4698/4699 in its
Security log - which
[requires Success auditing on the *Other Object Access Events* subcategory](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-object-access-events),
part of this kit's Core tier; confirm it
first or the tracer reports a false forwarding failure), then watch it
cross each hop: source Security log -> collector ForwardedEvents ->
workspace:

```kusto
WindowsEvent
| where TimeGenerated > ago(1h) and EventID == 4698
| where Computer == "<member server fqdn>"
| project TimeGenerated, Computer, Channel, EventData
```

A one-sentence acceptance criterion that exercises all four layers: *a
tracer event generated on a nominated source appears in WindowsEvent with
the source's Computer name within [delivery-mode floor + margin] minutes.*

## Query pack

**Fleet inventory** - who is arriving, how much, how fresh. If only the
collector's own name appears, the DCR reads the wrong channel:

```kusto
WindowsEvent
| where TimeGenerated > ago(24h)
| summarize Events = count(), Channels = dcount(Channel), LastSeen = max(TimeGenerated) by Computer
| order by Events desc
```

**Agent presence** - a machine with its own AMA heartbeats; a
forwarded-only source does not. Neither direction is absolute proof of
path: an agented machine can be collected directly *and* forward through
a subscription, and a missing heartbeat can also mean a
[broken agent or ingestion failure](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-troubleshoot-windows-vm)
rather than no agent. Use this to see whether WEF is likely in play, then
confirm any suspected path against the machine's own DCR associations:

```kusto
let agented = Heartbeat
    | where TimeGenerated > ago(24h) and Category == "Azure Monitor Agent"
    | distinct Computer;
WindowsEvent
| where TimeGenerated > ago(24h)
| summarize Events = count(), Channels = dcount(Channel) by Computer
| extend HasAgent = iff(Computer in (agented), "heartbeat present (direct collection possible)", "no heartbeat observed (forwarding likely)")
| order by Events desc
```

**Channel and event mix** - compare against the subscription query and the
source baseline (the [Reference page](reference.md) lists what each kit
setting emits):

```kusto
WindowsEvent
| where TimeGenerated > ago(24h)
| summarize Computers = dcount(Computer), Events = count() by Channel, EventID
| order by Events desc
```

**Collection-policy fingerprinting** - machines sharing an identical
channel set are almost certainly under the same DCR or subscription; the
distinct fingerprints recover the collection design from the data alone:

```kusto
WindowsEvent
| where TimeGenerated > ago(24h)
| summarize ChannelSet = make_set(Channel) by Computer
| extend Fingerprint = hash_sha256(tostring(array_sort_asc(ChannelSet)))
| summarize Machines = make_set(Computer), Count = dcount(Computer) by Fingerprint
| order by Count desc
```

**Silent sources** - previously seen, gone quiet (the workspace-side twin
of `wecutil gr`):

```kusto
WindowsEvent
| where TimeGenerated > ago(7d)
| summarize LastSeen = max(TimeGenerated) by Computer
| where LastSeen < ago(2h)
| order by LastSeen asc
```

**Never-seen sources** - diff the expected fleet against reality.
`set_difference` compares exact strings and `Computer` usually carries the
FQDN, so list the expected fleet as FQDNs (or normalise both sides):

```kusto
let expected = dynamic(["server1.corp.example", "server2.corp.example"]);
let seen = toscalar(WindowsEvent | where TimeGenerated > ago(24h) | summarize make_set(Computer));
print missing = set_difference(expected, seen)
```

**Ingestion latency** - against whatever target applies, remembering the
subscription delivery mode sets the floor before Azure is involved. One
caveat: if the DCR sets `UseTimeReceivedForForwardedEvents`, AMA stamps
`TimeGenerated` with the collector's receipt time, so this measures only
the post-receipt hop; leave that setting off to measure source-to-table:

```kusto
WindowsEvent
| where TimeGenerated > ago(24h)
| extend lag = ingestion_time() - TimeGenerated
| summarize p50 = percentile(lag, 50), p95 = percentile(lag, 95) by Computer
| order by p95 desc
```

**Volume and cost attribution** - the evidence for filtering further left
(source config, subscription query, or a
[DCR transform](https://learn.microsoft.com/azure/azure-monitor/data-collection/data-collection-transformations)):

```kusto
WindowsEvent
| where TimeGenerated > ago(7d) and _IsBillable == true
| summarize GB = sum(_BilledSize) / 1e9 by bin(TimeGenerated, 1d)
```

```kusto
WindowsEvent
| where TimeGenerated > ago(24h) and _IsBillable == true
| summarize GB = sum(_BilledSize) / 1e9 by Computer, Channel
| order by GB desc
```

**Payload spot check** - pulling fields from the dynamic bag (4688 with
command line, assuming the source enables the kit's
[HighVolume tier](baselines.md#tiers)):

```kusto
WindowsEvent
| where TimeGenerated > ago(1h)
| where Channel == "Security" and EventID == 4688
| extend NewProcess = tostring(EventData.NewProcessName), CmdLine = tostring(EventData.CommandLine)
| project TimeGenerated, Computer, NewProcess, CmdLine
| take 20
```

## The reconciliation that matters

The single most useful standing assertion is a three-list comparison, and
none of the lists comes from a status page:

1. the intended fleet (the AD group scoping the subscription),
2. the collector's registered Active sources (`wecutil gr`),
3. distinct `Computer` values in `WindowsEvent` over 24 hours.

Equal counts and matching names show the chain is delivering for those
machines. Every gap has at least one broken hop behind it, and the
queries above narrow down which.
