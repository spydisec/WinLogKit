# ATT&CK mapping snapshot (the kit's native mapping)

The data behind `Export-AttackCoverage.ps1`. Two files, two very different
origins - kept separate on purpose:

| File | What it is | Origin |
|---|---|---|
| `windows_analytics.csv` | Windows technique -> analytic log source -> event codes, flattened from MITRE ATT&CK's own detection strategies/analytics model | **Derived from MITRE ATT&CK Enterprise v19.2 STIX data** (`attack-stix-data`, extracted 2026-08-31): `detection-strategy --detects--> technique`, strategy analytics filtered to platform Windows, each analytic's `x_mitre_log_source_references` (name + `EventCode=` channel) emitted as rows. Revoked/deprecated objects excluded. |
| `event_map.csv` | log source / event code -> the kit item that produces it (audit subcategory GUID, channel, and any registry prerequisite) | **Curated by this kit**, one row per claim, grounded in Microsoft's advanced audit policy documentation and Yamato's ConfiguringSecurityLogAuditPolicies guide (the same sources as the settings table). Rows with `status=NotInKit` are honest statements that the producing subcategory is outside the baseline. |

`event_map.csv` columns: `match_source` and `match_event` (the ATT&CK log
source and event code; an empty event matches any code from that source),
`item_type` / `item_id` / `prereq` (the kit item that produces it), `status`
and `note` (for sources the kit doesn't cover: `NotInKit`, `NotNative` or
`RequiresSysmon`, with the reason), and `technique_id` (optional: the row
applies to that technique only). Lookup order: exact event (technique row,
then general), then the source-wide rows. Technique rows exist because some
analytics name a bare `WinEventLog:Security` with no event code, and only
the technique says what they mean. When an analytic has no event codes but
its detail text names them (`EventCode=4778`), those are used.

Sources not mapped in `event_map.csv` are classified by prefix at runtime:
`WinEventLog:Sysmon` -> RequiresSysmon; `etw:`/`EDR:`/`NSM:`/`m365:`/
`azure:`/`dns:`/`Windows:perfmon` -> NotNative (ETW tracing, EDR, network
sensors and cloud logs are outside native host logging); anything else ->
Unmapped (reported, so curation gaps stay visible instead of silently
counting either way).

**Curation status:** 0 Unmapped analytic rows as of 2026-09-24 (ATT&CK
v19.2). Where ATT&CK attributes an event to the wrong log (Security 1074 is
User32's shutdown event in the System log; Security 3033 is a Code
Integrity event), the row maps it to the log that actually produces it and
says so in `note`; each such claim was checked against the provider's own
event definitions or a live event.

**Nothing is fetched at runtime.**

## Refreshing the snapshot

**When:** with each ATT&CK release that changes Enterprise detection
strategies or analytics (MITRE ships two major releases a year), and at
least once a year.

**Steps:**

1. Download the current `enterprise-attack.json` from
   [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).
2. Re-derive `windows_analytics.csv` as described above (detection
   strategies -> techniques, Windows analytics only, each analytic's log
   source references as rows; revoked and deprecated objects excluded).
3. Update the version and date here, in `tools\Export-AttackCoverage.ps1`
   (its description and `$mappingDesc`) and in `tools\reference-baselines.psd1`
   if its extraction date moves.
4. Run `.\tools\Export-AttackCoverage.ps1 -IncludeHighVolume` and work the
   Unmapped rows in the detail CSV down to 0: map each source to the kit
   item that produces it, or give it a status and a note. The self-checks
   fail while any row is Unmapped.
5. Regenerate the numbers on the Coverage and Baselines pages (Core, Core +
   HighVolume, the three role presets, the Microsoft client reference) and
   the Reference page (`.\tools\Export-ReferenceTable.ps1`), and date them.
## Attribution

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
  `windows_analytics.csv` is derived from ATT&CK content, © 2026 The MITRE
  Corporation, used per the
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
  This kit is not affiliated with or endorsed by MITRE.
