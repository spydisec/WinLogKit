# OSSEM-DM snapshot

Vendored data from the [OSSEM Detection Model](https://github.com/OTRF/OSSEM-DM)
(Open Source Security Events Metadata, Open Threat Research Forge, MIT
licensed), which maps MITRE ATT&CK techniques and data components to the
Windows events that make them observable.

| File | What it is |
|---|---|
| `attack_events_mapping.csv` | Verbatim copy of `use-cases/mitre_attack/attack_events_mapping.csv`: ATT&CK data components -> event IDs -> audit subcategory / channel, including the enable commands. |
| `techniques_to_events_windows.csv` | Derived, Windows-only flattening of `use-cases/mitre_attack/techniques_to_events_mapping.json` (10 MB upstream, reduced to the columns the kit joins on: technique, tactics, data source/component, event id, channel, audit subcategory). |

**Provenance**: OSSEM-DM commit `9f9373d86ab9`, extracted 2026-08-31.
This is a static snapshot - the kit never fetches OSSEM (or anything else)
at runtime. To refresh: clone OSSEM-DM, re-derive with the documented
columns (windows platform rows, deduplicated), and update this provenance
line in the same PR.

Consumed by `Export-AttackCoverage.ps1`, which joins these mappings to the
kit's settings table to report which ATT&CK techniques a given baseline
selection makes observable, and why the rest are not (deselected, excluded
from the kit by design, or Sysmon-only).
