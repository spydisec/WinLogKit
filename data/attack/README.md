# ATT&CK mapping snapshot (the kit's native mapping)

The data behind `Export-AttackCoverage.ps1`. Two files, two very different
origins - kept separate on purpose:

| File | What it is | Origin |
|---|---|---|
| `windows_analytics.csv` | Windows technique -> analytic log source -> event codes, flattened from MITRE ATT&CK's own detection strategies/analytics model | **Derived from MITRE ATT&CK Enterprise v19.2 STIX data** (`attack-stix-data`, extracted 2026-08-31): `detection-strategy --detects--> technique`, strategy analytics filtered to platform Windows, each analytic's `x_mitre_log_source_references` (name + `EventCode=` channel) emitted as rows. Revoked/deprecated objects excluded. |
| `event_map.csv` | log source / event code -> the kit item that produces it (audit subcategory GUID, channel, and any registry prerequisite) | **Curated by this kit**, one row per claim, grounded in Microsoft's advanced audit policy documentation and Yamato's ConfiguringSecurityLogAuditPolicies guide (the same sources as the settings table). Rows with `status=NotInKit` are honest statements that the producing subcategory is outside the baseline. |

Sources not mapped in `event_map.csv` are classified by prefix at runtime:
`WinEventLog:Sysmon` -> RequiresSysmon; `etw:`/`EDR:`/`NSM:`/`m365:`/
`azure:`/`dns:`/`Windows:perfmon` -> NotNative (ETW tracing, EDR, network
sensors and cloud logs are outside native host logging); anything else ->
Unmapped (reported, so curation gaps stay visible instead of silently
counting either way).

**Nothing is fetched at runtime.** To refresh the snapshot: download the
current `enterprise-attack.json` from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data),
re-derive `windows_analytics.csv` per the description above, update the
version/date here, and extend `event_map.csv` for any new event codes the
release introduces (the Unmapped count in the coverage output is the
worklist).

## Attribution

- MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
  `windows_analytics.csv` is derived from ATT&CK content, © 2026 The MITRE
  Corporation, used per the
  [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
  This kit is not affiliated with or endorsed by MITRE.
- The idea of joining host logging configuration to ATT&CK through event
  metadata follows OTRF's [OSSEM-DM](https://github.com/OTRF/OSSEM-DM)
  (MIT), whose snapshot the kit retains in `data/ossem/` for cross-checking
  (`Export-AttackCoverage.ps1 -UseOssem`). Credit where due: OSSEM proved
  the approach; this native mapping updates it against current ATT&CK.
