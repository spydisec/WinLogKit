# ATT&CK Coverage Mapping

Which MITRE ATT&CK techniques does a given baseline make observable - and
for the ones it doesn't, exactly why not? `Export-AttackCoverage.ps1`
answers this locally, for any selection, from vendored snapshots - nothing
is fetched at runtime.

## How the native mapping works

Two data files in `data/attack/` (provenance and attribution in its README):

1. **`windows_analytics.csv`** - derived from **MITRE ATT&CK Enterprise
   v19.2's own detection model** (snapshot 2026-08-31): detection strategies
   link techniques to per-platform analytics, and Windows analytics name
   their log sources literally (`WinEventLog:Security`, `EventCode=4688`,
   ...). Flattened, that gives technique -> log source -> event codes,
   straight from MITRE's current data.
2. **`event_map.csv`** - the kit-curated join: each log source / event code
   mapped to the settings-table item that produces it (audit subcategory
   GUID, channel, and any registry prerequisite such as script block
   logging), one sourced row per claim.

```powershell
.\Export-AttackCoverage.ps1                                        # Core tier
.\Export-AttackCoverage.ps1 -IncludeHighVolume
.\Export-AttackCoverage.ps1 -BaselineFile .\presets\role_Workstation.csv
```

Every technique verdict carries a reason:

| Status | Meaning |
|---|---|
| Observable | an enabling item is selected - the events will exist |
| NotSelected | the kit has the item, but this selection excludes it |
| NotInKit | needs a subcategory the kit deliberately excludes (SACL-dependent Registry/File System, DS Replication, ...) |
| RequiresSysmon | only Sysmon telemetry maps to it - out of kit scope by design |
| NotNative | needs ETW tracing, EDR, network sensors or cloud logs |
| Unmapped | ATT&CK names a source the curated map doesn't cover yet - the visible curation worklist |

## Reference numbers (ATT&CK v19.2: 472 Windows techniques with analytics)

An important context number first: MITRE's current analytics catalogue is
Sysmon-first - **176 of the 472 techniques are Sysmon-only and another 12
need ETW/EDR/network/cloud telemetry**, so the ceiling for *any* native
host-logging configuration is **284 techniques**. Against that ceiling:

| Selection | Observable | Of the native ceiling (284) |
|---|---|---|
| Core tier | 162 | 57% |
| **Core + HighVolume** | **279** | **98%** |
| role_Workstation preset | 265 | 93% |
| role_DomainController preset | 273 | 96% |
| role_MemberServer preset | 263 | 93% |
| Microsoft_Client preset | 166 | 58% |

Read that middle row carefully: with the HighVolume tier on, the kit reaches
**279 of the 284 natively-reachable techniques** - the 5 missed are 1
excluded-subcategory technique and 4 unmapped-source curation items. The
Core -> HighVolume jump (117 techniques) is the quantified case for that
tier's volume cost; the per-setting breakdown is in the detail CSV's
`ProvidedBy` column.

## Outputs

- `Results\AttackCoverage_Detail_*.csv` - every analytic mapping row with
  status and which kit item provides it
- `Results\AttackCoverage_Gaps_*.csv` - techniques not observable, with the
  dominant reason

## OSSEM cross-check

The approach of joining logging configuration to ATT&CK through event
metadata was proven by OTRF's [OSSEM-DM](https://github.com/OTRF/OSSEM-DM)
(MIT) - full credit in `data/attack/README.md`. The kit retains its OSSEM
snapshot and `-UseOssem` runs the legacy join as an independent cross-check
(note it maps an older ATT&CK vintage with a different technique set, so
its numbers are not directly comparable to the native mapping's).

## Caveats

- This maps **events, not detections**: "observable" means the raw events
  exist; detection still needs rules (Sigma, SIEM analytics).
- A technique counts as observable when at least one of its ATT&CK analytics
  has at least one producible log source - the optimistic reading;
  analytics often correlate multiple sources for fidelity.
- PowerShell 4103/4104 rows enforce their registry prerequisites (module /
  script block logging policies, per
  [Microsoft's PowerShell logging documentation](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows)).
- Snapshots are point-in-time; refresh procedure in `data/attack/README.md`.
