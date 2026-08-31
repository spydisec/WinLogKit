# ATT&CK Coverage Mapping

The kit organises settings by **behaviour category** (Authentication,
Execution, Persistence, ...) so a monitoring requirement traces to the exact
settings that satisfy it. This page adds the second axis:
**MITRE ATT&CK techniques**, via the
[OSSEM Detection Model](https://github.com/OTRF/OSSEM-DM) (Open Threat
Research Forge, MIT) - the same data behind OSSEM's
[techniques-to-events](https://ossemproject.com/dm/mitre_attack/attack_techniques_to_events.html)
page, computed locally for *your* selection.

## How it works

OSSEM-DM maps ATT&CK data components to concrete Windows events
(technique -> data component -> event ID -> audit subcategory / channel).
The kit vendors a Windows-only snapshot of that mapping in `data\ossem\`
(provenance recorded there - **nothing is fetched at runtime**) and joins
it against the settings table:

```powershell
.\Export-AttackCoverage.ps1                                  # Core tier
.\Export-AttackCoverage.ps1 -IncludeHighVolume               # Core + HighVolume
.\Export-AttackCoverage.ps1 -BaselineFile .\presets\ASD.csv  # any selection
```

Every mapping row is classified, and every technique verdict comes with a
*reason*:

| Status | Meaning |
|---|---|
| Observable | the enabling item is selected - the events will exist |
| NotSelected | the kit has the item, but this selection excludes it (often the HighVolume tier) |
| NotInKit | needs a subcategory the kit deliberately excludes (SACL-dependent Registry / File System / Kernel Object, Process Termination, ...) |
| RequiresSysmon | only Sysmon telemetry maps to it - native logging cannot see it |

## Reference numbers (OSSEM-DM snapshot, 362 mapped Windows techniques)

| Selection | Observable techniques |
|---|---|
| Core tier | 152 |
| Core + HighVolume | 320 |
| Microsoft_Client preset | 289 |

The Core -> HighVolume jump of **168 techniques** is the quantified value of
process creation + command line and PowerShell logging - the number to put
next to the volume cost when that decision is made. (The classifier is
strict: PowerShell 4103/4104 rows count only when their enabling registry
policy is selected, not merely the channel - which is also why the
Microsoft_Client preset, which includes process creation, outscores the
deliberately conservative Core tier.) The residual ~40 are split between
deliberately excluded subcategories and Sysmon-only telemetry: known,
stated limits of native logging, not silent gaps.

## Outputs

- `Results\AttackCoverage_Detail_*.csv` - every mapping row: technique,
  tactic, data component, event ID, channel/subcategory, status, and which
  kit item provides it
- `Results\AttackCoverage_Gaps_*.csv` - techniques not observable, with the
  dominant reason - the "what would enabling X buy me" worklist

## Behaviour categories -> settings

The category-to-settings mapping (which subcategories, channels and
registry values serve each of the 16 behaviour categories, with
full/partial coverage stated honestly) lives in the
[README's category mapping table](https://github.com/spydisec/WinLogKit#category-mapping),
and interactively in the builder: `.\New-LoggingBaseline.ps1 -Show` renders
any selection as a tree with per-category coverage counts.

## Caveats

- OSSEM maps **events, not detections**: "observable" means the raw events
  exist; detection still needs rules (Sigma, your SIEM analytics).
- PowerShell Operational rows (4103/4104) require their enabling registry
  policies (module / script block logging); the classifier enforces that
  prerequisite rather than counting the channel alone.
- The snapshot is point-in-time (commit and date in
  `data\ossem\README.md`); refresh procedure is documented there.
- WELA's ATT&CK Navigator layers (`mitre-ttp-navigator-*.json` in its
  output) are a complementary view from the Sigma-rule angle.
