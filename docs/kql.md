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

An analogy that holds up well: the workspace is a filing cabinet and each
table is a drawer.

- **Two drawers look similar.** `SecurityEvent` is a *different* drawer
  with its own clerk: the *Windows Security Events via AMA* connector
  files a machine's **own** Security log into `SecurityEvent`. Put that
  clerk on a collector and it files the collector's own activity - the
  thousands of forwarded events sitting in its ForwardedEvents log are
  ignored. Practical consequence: a detection that only searches
  `SecurityEvent` never sees anything that travelled via WEF (ASIM
  parsers union both drawers - see
  [normalisation](https://learn.microsoft.com/azure/sentinel/normalization)).
- **Every document keeps its original letterhead.** Everything physically
  passed through the collector, but each event still records the machine
  that created it: `Computer` is the **original source**, not the
  collector. That is what makes fleet verification possible from the
  workspace end - you can list exactly which servers are represented
  without logging into anything.
- **The envelope is thrown away; the letter is kept.** ForwardedEvents
  was only the transport envelope. Once filed, each event shows its
  *original* log name (`Channel` = `Security` and so on), so "everything
  that came via forwarding" cannot be filtered for directly - it is
  inferred from the `Computer` names instead. And the event's details are
  not split into neat named columns the way `SecurityEvent`'s are; they
  sit bundled in one `EventData` field that queries unpack
  (`EventData.CommandLine`).
- **There is also a stamp saying which clerk filed it.** Every row
  carries
  [`_ResourceId`](https://learn.microsoft.com/azure/azure-monitor/logs/log-standard-columns#_resourceid)
  - the Azure resource the record is associated with, which for
  agent-collected data is the machine running the agent, i.e. the
  **collector** - while `Computer` stays the end device. That pair
  (collector stamp + original letterhead) powers the
  collector-attribution queries below; sanity-check the mapping in your
  own workspace by comparing against `Heartbeat._ResourceId`.

One real-world wrinkle: a single DCR can carry **two data sources** - a
Custom XPath one reading `ForwardedEvents!*` (those rows go to
`WindowsEvent`) *and* a Basic one collecting the collector's own
Application/Security/System logs (those rows go to the `Event` table).
Finding the collectors' own noise in `Event` rather than `WindowsEvent`
is the second source doing exactly what its checkboxes say, not a fault.

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

**Collection method map** - for every source, *how* its events reached
the workspace: direct AMA on the machine itself, or WEF via a named
collector. The row's `_ResourceId` is the machine whose agent shipped it,
so when the source's own name matches that resource, the machine shipped
its own events (direct); when it differs, the events rode a subscription
through that collector. Joining Heartbeat on the lowercased full
`_ResourceId` (never on computer names, whose short/FQDN forms differ
between tables) adds each shipping agent's health. Field-tested against a
mixed direct-and-forwarded estate:

```kusto
let Lookback = 24h;
let ActiveAgents =
    Heartbeat
    | where TimeGenerated > ago(Lookback) and Category == "Azure Monitor Agent"
    | extend AgentResourceId = tolower(_ResourceId)
    | summarize arg_max(TimeGenerated, Version, OSType) by AgentResourceId
    | project AgentResourceId, LastHeartbeat = TimeGenerated, AgentVersion = Version, OSType;
WindowsEvent
| where TimeGenerated > ago(Lookback)
| extend SourceComputer = tostring(Computer)
| extend SourceShortName = tolower(tostring(split(Computer, ".")[0]))
| extend AgentResourceId = tolower(tostring(_ResourceId))
| extend Collector = extract(@"([^/]+)$", 1, AgentResourceId)
| extend CollectorShortName = tolower(tostring(split(Collector, ".")[0]))
| summarize
    Events = count(),
    Channels = dcount(Channel),
    FirstEvent = min(TimeGenerated),
    LastEvent = max(TimeGenerated)
    by SourceComputer, SourceShortName, Collector, CollectorShortName, AgentResourceId
| join kind=leftouter ActiveAgents on AgentResourceId
| extend CollectionMethod = case(
    isempty(AgentResourceId), "Unknown - Resource ID unavailable",
    SourceShortName == CollectorShortName, "Direct AMA",
    strcat("WEF via collector: ", Collector))
| extend CollectorHeartbeatStatus =
    iff(isnotempty(LastHeartbeat), "Active", "No heartbeat in last 24h")
| project
    SourceComputer, CollectionMethod, Collector, CollectorHeartbeatStatus,
    LastHeartbeat, AgentVersion, Events, Channels, FirstEvent, LastEvent
| order by CollectionMethod asc, Events desc
```

One row per source, and the `CollectionMethod` column answers the
question directly; `CollectorHeartbeatStatus` flags a shipping agent that
has since gone quiet. (Absence of a heartbeat is evidence within the
window, not proof the machine is down - see the
[agent troubleshooting](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-troubleshoot-windows-vm).)

**Per-collector rollup of observed events** - how balanced the shipping
collectors are. There is no "DCR name" column in the table, so scope by
the machines listed on the DCR's **Resources** tab (add
`| where Collector in ("wec01", "wec02", ...)` when other machines also
write to `WindowsEvent`). `TimeGenerated` is when an event happened on
the source; `ingestion_time()` is when the workspace received it - this
query windows and reports on the latter, since delivery freshness is the
claim being made
([standard columns](https://learn.microsoft.com/azure/azure-monitor/logs/log-standard-columns)).
A collector that shipped nothing cannot appear here; the next section
finds those:

```kusto
WindowsEvent
| where ingestion_time() > ago(24h)
| extend Collector = tolower(tostring(split(_ResourceId, "/")[-1]))
| summarize Events = count(), EndDevices = dcount(Computer), LastIngested = max(ingestion_time()) by Collector
| order by Events desc
```

And if the DCR also carries a Basic data source for the collectors' own
Application/Security/System logs, those rows are in the `Event` table:

```kusto
Event
| where TimeGenerated > ago(24h)
| extend Collector = tolower(tostring(split(_ResourceId, "/")[-1]))
| summarize Events = count() by Collector, EventLog
| order by Collector asc, Events desc
```

**Silent collectors: attached to the DCR but forwarding nothing.** The
rollup above only shows collectors that shipped at least one row - a dead
collector is invisible in it. This version starts from the machines that
*should* be shipping (their AMA heartbeats) and left-joins what actually
arrived, so the silent ones surface with zero counts. Replace the list
with the names from the DCR's Resources tab:

Both sides derive the collector name from `_ResourceId` (present on
[both tables](https://learn.microsoft.com/azure/azure-monitor/logs/log-standard-columns#_resourceid))
so the join key cannot disagree on short name vs FQDN; only the
`expectedCollectors` list needs to match the resource names from the
Resources tab (lowercase, to match the `tolower` normalisation):

```kusto
let window = 24h;
let expectedCollectors = dynamic(["wec01", "wec02", "wec03", "wec04", "wec05"]);
let shipping = WindowsEvent
    | where ingestion_time() > ago(window)
    | extend Collector = tolower(tostring(split(_ResourceId, "/")[-1]))
    | summarize Events = count(), EndDevices = dcount(Computer), LastIngested = max(ingestion_time()) by Collector;
let alive = Heartbeat
    | where TimeGenerated > ago(window) and Category == "Azure Monitor Agent"
    | extend Collector = tolower(tostring(split(_ResourceId, "/")[-1]))
    | summarize LastHeartbeat = max(TimeGenerated) by Collector;
print Collector = expectedCollectors
| mv-expand Collector to typeof(string)
| join kind=leftouter alive on Collector
| join kind=leftouter shipping on Collector
| project Collector, LastHeartbeat, Events = coalesce(Events, 0), EndDevices = coalesce(EndDevices, 0), LastIngested
| order by Events asc
```

Reading the result rows for a silent collector, in order (heartbeat
presence or absence here means *within this query's window and filters* -
it is evidence, not proof, of a machine's state):

1. **No matching heartbeat** - the machine, its agent, or heartbeat
   ingestion is not working (or the name in `expectedCollectors` does not
   match the resource name); nothing about WEF yet. Start with the
   [agent troubleshooting](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-troubleshoot-windows-vm).
2. **Heartbeat present, events zero** - the agent reports in but ships no
   forwarded events; the question becomes *which side of the collector is
   broken*. On that collector,
   check whether ForwardedEvents itself has recent events:

   ```powershell
   Get-WinEvent -LogName ForwardedEvents -MaxEvents 5 | Select-Object TimeCreated, MachineName, Id
   ```

    - **ForwardedEvents has recent events** -> the WEF half works; the
      workspace hop is broken *for this machine*. Verify the DCR
      association actually includes it (a five-collector estate where
      only three were ever associated looks exactly like this) and grep
      the local config cache for `ForwardedEvents` as in the four-layer
      check above.
    - **ForwardedEvents is empty or stale** -> the WEF half is broken:
      run `wecutil es` / `wecutil gr` on that collector. No subscriptions
      = it was never set up; subscriptions with zero or Inactive sources
      = work the [WEC page's](wec.md) reconciliation and silent-failures
      table (GPO scope, WinRM, the Security-log permission). It is
      entirely possible for some collectors in an estate to have
      subscriptions and others none - each collector's subscription store
      is local to it.

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

## Domain controllers: which path are they on?

DCs are usually the highest-value sources and often the messiest to
trace, because one DC's telemetry can arrive over **three separate
paths** into **three separate tables**:

| DC telemetry | Path | Table |
|---|---|---|
| Security / directory events via WEF | DC -> collector -> AMA | `WindowsEvent` |
| Security events via direct AMA (the [Security Events connector](https://learn.microsoft.com/azure/sentinel/connect-services-windows-based) on the DC itself) | DC -> AMA | `SecurityEvent` |
| DNS server activity (the [ASIM DNS via AMA connector](https://learn.microsoft.com/azure/sentinel/dns-normalization-schema)) | DC -> AMA | `ASimDnsActivityLogs` |

The DNS path can never ride WEF - that connector's DCR runs on the DNS
server (typically the DCs) itself - so DNS rows are always evidence of a
working *direct* agent on that DC.

Which tables each DC is actually landing in (short names, lowercase):

```kusto
let DCs = dynamic(["dc01", "dc02"]);
union isfuzzy=true
    (WindowsEvent        | where TimeGenerated > ago(24h) | extend Table = "WindowsEvent",        Host = tolower(tostring(split(Computer, ".")[0]))),
    (SecurityEvent       | where TimeGenerated > ago(24h) | extend Table = "SecurityEvent",       Host = tolower(tostring(split(Computer, ".")[0]))),
    (ASimDnsActivityLogs | where TimeGenerated > ago(24h) | extend Table = "ASimDnsActivityLogs", Host = tolower(tostring(split(coalesce(DvcHostname, Dvc), ".")[0])))
| where Host in (DCs)
| summarize Events = count(), LastIngested = max(ingestion_time()) by Host, Table
| order by Host asc, Table asc
```

A DC missing a row for an expected table means **no matching rows were
observed in the window** - strong evidence, not proof, that the path is
broken: the path may be deliberately unconfigured for that DC, or a
[DCR XPath filter](https://learn.microsoft.com/azure/azure-monitor/vm/data-collection-windows-events)
may exclude the events. Interpret against the intended design, then
confirm with the tracer-event and configuration checks above before
declaring it broken. For the `WindowsEvent` rows, *how* each DC arrives
(WEF via which collector, or direct) is the collection method map above -
insert `| where SourceShortName in (DCs)` before its `project`.

(`Host` in the DNS leg prefers `DvcHostname` and falls back to `Dvc`,
which per the
[ASIM device schema](https://learn.microsoft.com/azure/sentinel/normalization-entity-device)
can also carry an IP or device ID - rows where the fallback is not a
hostname will not match the `DCs` list.)

And which machines are shipping DNS activity at all (field-tested; the
resource ID also says whether each is an Arc-enabled server or an Azure
VM):

```kusto
ASimDnsActivityLogs
| where TimeGenerated > ago(24h)
| summarize Events = count(), LastIngested = max(ingestion_time()) by _ResourceId
| extend Machine = tolower(tostring(split(trim_end(@"/", _ResourceId), "/")[-1]))
| extend HostType = case(
    _ResourceId has "/microsoft.hybridcompute/machines/", "Arc-enabled server",
    _ResourceId has "/microsoft.compute/virtualmachines/", "Azure VM",
    "Other")
| project Machine, HostType, Events, LastIngested, _ResourceId
| order by Machine asc
```

An on-prem DC expected here but absent shipped no matching DNS rows in
the window - triage it like any silent direct-AMA machine (heartbeat,
DCR association, config cache), not like a WEF problem.

## The reconciliation that matters

The single most useful standing assertion is a three-list comparison, and
none of the lists comes from a status page:

1. the intended fleet (the AD group scoping the subscription),
2. the collector's registered Active sources (`wecutil gr`),
3. distinct `Computer` values in `WindowsEvent` over 24 hours.

Equal counts and matching names show the chain is delivering for those
machines. Every gap has at least one broken hop behind it, and the
queries above narrow down which.
