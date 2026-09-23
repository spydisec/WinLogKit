# ADR-002: Project scope and simplification for v2

**Status:** Accepted (Option B, 2026-09-23)
**Date:** 2026-09-23
**Deciders:** Maintainer (@spydisec)
**Supersedes:** nothing. Follows [ADR-001](https://github.com/spydisec/WinLogKit/pull/30) (v1.0 layout and docs cut).

## Context

WinLogKit started as "apply the Yamato Security logging baseline safely" and grew one useful feature at a time. At v1.0 the repository holds:

| Area | What it is | Size |
|---|---|---|
| Host scripts | `Enable-`, `Test-`, `New-LoggingBaseline.ps1`, settings table, shared helpers | ~1,800 lines |
| Selection | 3 tiers (Core, HighVolume, Optional), 10 presets, an interactive CSV builder | 10 CSVs |
| Fleet | Intune remediation pack, GPO pack, WEF subscription generator, WEF filter tester | ~900 lines |
| Report | ATT&CK coverage report, WELA check (downloads a third-party tool) | ~460 lines |
| Add-on | AutorunsToWinEventLog (Sysinternals `autorunsc`, scheduled task) | ~520 lines + docs |
| Data | ATT&CK snapshot, OSSEM mappings, WEF event-ID table | ~1.1 MB |
| Docs | 10 pages plus a 390-line Sentinel KQL extra | ~1,800 lines |

Signs that the scope has drifted past what a new user can take in:

- **Transcription (#34).** An Optional item filled a test workstation's Documents folder with 1,587 files in 3 weeks. Making it safe needed about 250 more lines (folder ACL, retention, special cases in four scripts). It was removed instead (#36). The lesson: anything that isn't "a native event log setting" costs far more than it looks.
- **Three ways to choose settings** (tier switches, presets, builder CSV), and presets that nearly duplicate each other. `role_Workstation` and `spydi_Workstation_Minimal` differ by one audit subcategory.
- **Things that break the kit's own rules.** The kit is "no agents, no downloads", yet the Autoruns add-on needs Sysinternals and the WELA check downloads WELA.
- **Legacy weight.** `data/ossem/` (917 KB) is read only by the coverage report's legacy `-UseOssem` cross-check mode; the report's default mapping uses `data/attack/`.
- **Out-of-scope docs.** The kit "ends at the collector", yet it ships a Sentinel KQL page with 10 unresolved review findings.
- **Roadmap items never landed.** ADR-001's roadmap list was never turned into issues, so the backlog isn't visible.

The questions this ADR answers: what is WinLogKit for, who is it for, and what does it stop doing?

## Decision

### 1. Goal (one sentence, used in the README)

> **WinLogKit turns on the native Windows event logging that security monitoring needs, proves it is recording, and can undo it, on Windows servers and endpoints, from one sourced settings table.**

In scope: configuring the host's own logging (audit policy, event channels, logging-related registry policy), verifying it, rolling it back, and getting the same selection onto a fleet.
Out of scope: anything that writes files outside the event log, installs agents or third-party binaries, or runs after the event leaves the host's collector (SIEM content, parsers, detections).

### 2. Answers to the four questions

| # | Question | Decision | Reason |
|---|---|---|---|
| 1 | Endpoints and servers, or servers only? | **Both.** Windows 10/11 and Server 2019+. | The mechanism is identical (auditpol, channels, registry); only the selection differs by role. Dropping endpoints saves no code and loses the largest audience. |
| 2 | Baselines for SMB / enterprise? | **Yes, this is the core product.** Simplify how people pick one (below). | A sourced, explained, safe baseline is what people can't easily get elsewhere. SMBs need a sane default; enterprises need a CSV they can review and change. Both are served by role presets plus the builder. |
| 3 | Sending logs to WEC? | **Keep WEF as the one built-in collection path, in its simple form.** | Native and agentless, like the rest of the kit, and the only free central collection most SMBs have. The Security-channel event-ID narrowing (`-Filter Baseline`) and its tester are advanced tuning that fails silently when wrong (dropped events). Enterprises with a SIEM can filter at ingest instead (for example Sentinel DCR transforms). |
| 4 | Intune pack, overkill? | **Keep.** It's how cloud-managed endpoints get the baseline. | Without AD there is no GPO, and Intune remediations are the native route for Windows 10/11 fleets. It's generated from the settings table, so it adds no new settings logic. Mark it "not yet field-tested" until it is. |

### 3. What stays, what goes

| Component | Decision | Why |
|---|---|---|
| Settings table, Enable, Test, rollback | **Keep** | The product. |
| New-LoggingBaseline (builder) | **Keep** | The customisation path for enterprises. |
| Tiers | **Two: Core and HighVolume.** Drop Optional and `-IncludeOptional`. | Optional now holds 2 items (Crypto-DPAPI debug channel, IPsec Driver). Move them to HighVolume ("opt in after a pilot"). One fewer switch in every script. |
| Presets | **10 to 4:** `Workstation`, `MemberServer`, `DomainController`, plus `ASD` as the one external reference. | The `spydi_*` Minimal/Heavy pairs nearly duplicate the role presets. "Heavy" is the role preset plus `-IncludeHighVolume`. The Microsoft client/server reference presets (15 to 17 items) are narrower than Core and confuse the choice. |
| Intune pack | **Keep** | Question 4. |
| GPO pack | **Keep** | Small (135 lines), and the AD-joined route. |
| WEF subscription (`-Filter Channel`) | **Keep** | Question 3. |
| WEF `-Filter Baseline`, `Test-WefFilter.ps1`, `tools/Update-AuditSubcategoryEvents.ps1`, `data/wef/`, `$BaselineWefSuppress` Suppress rules | **Remove** | Tuning that is easy to get wrong silently (dropped events), and a maintained data snapshot. Document "filter at your SIEM ingest layer" instead. |
| ATT&CK coverage report + `data/attack/` | **Move to `tools/`** as a maintainer script that produces the numbers on the Coverage page. | The numbers justify the tiers and are worth publishing, but a user doesn't need to run it to deploy logging. |
| `data/ossem/` and the report's `-UseOssem` mode | **Remove** | A second, legacy mapping kept only as a cross-check; the default native mapping (`data/attack/`) stays. |
| WELA check (`report/Invoke-WELACheck.ps1`) | **Remove** | Downloads a third-party tool. Test already verifies the live state. Link to WELA from the docs for anyone who wants a second opinion. |
| AutorunsToWinEventLog add-on | **Delete** (first decided as "move to its own repository"; the maintainer changed this to delete on 2026-09-23) | Needs Sysinternals and a scheduled task, the one exception to the kit's no-agent rule. |
| `docs/extras/sentinel-kql.md` | **Remove** | Past the kit's boundary (after the collector), SIEM-specific, and unvalidated (10 open findings). |
| PowerShell transcription | **Removed** (#36) | Writes files outside the event log. Script block logging (4104) covers it. |

### 4. Rules for future additions

A new setting or feature goes in only if **all** of these hold:

1. It configures, verifies or delivers a **native Windows event log** setting.
2. It needs **no download, agent, service or scheduled task**.
3. It fits into the existing flow (settings table, then Enable / Test / Rollback, then fleet generators) **without a new item type**, or the ADR proposing it explains why a new type is worth it.
4. It has a named source (Yamato, ASD, Microsoft) or a documented reason.

## Options considered

### Option A: Keep everything, improve the docs
| Dimension | Assessment |
|---|---|
| Complexity | High, unchanged |
| Effort | Low |
| Learning curve for a new user | Steep: 10 presets, 3 tiers, 11 user-facing scripts |
| Maintenance | High: third-party dependencies, data snapshots, SIEM-specific content |

**Pros:** no breaking change, no lost features.
**Cons:** doesn't answer "what is this for"; every future feature request lands on the same unclear boundary; the transcription problem will happen again in another form.

### Option B: Focused kit (recommended)
| Dimension | Assessment |
|---|---|
| Complexity | Medium: 3 host scripts, 3 fleet generators, 4 presets, 2 tiers |
| Effort | Medium: one release of removals plus doc updates |
| Learning curve | "Pick your role preset, run Enable, run Test" |
| Maintenance | Lower: no downloads, one data snapshot (ATT&CK, maintainer-only) |

**Pros:** a clear boundary for saying yes or no to requests; about 1,500 fewer lines and 1 MB less data; the README can explain the whole kit on one screen.
**Cons:** a breaking v2.0.0 (preset names, `-IncludeOptional`, removed scripts); users of WEF narrowing or the Autoruns add-on need to move to another approach.

### Option C: Servers only, host scripts only
| Dimension | Assessment |
|---|---|
| Complexity | Low |
| Effort | Medium |
| Learning curve | Lowest |
| Maintenance | Lowest |

**Pros:** the smallest possible kit.
**Cons:** drops endpoints (no code saved, largest audience lost) and all fleet delivery, so every organisation rebuilds deployment itself, which is where copy-paste drift from the tested baseline comes back.

## Trade-off analysis

The deciding question is whether a component helps someone **turn on, prove or deliver native logging**. Option B keeps everything that does (including Intune and GPO, which are thin generated layers over the same table) and removes what doesn't (downloads, agents, post-collector content, unused data, near-duplicate presets). Option C over-corrects: it removes fleet delivery, which is the part that keeps deployed config identical to the tested baseline. Option A leaves the boundary unclear, which is the root cause of #34.

## Consequences

- **Easier:** onboarding (one goal, four presets, two tiers); deciding feature requests (section 4); reviews and CI (fewer scripts and data snapshots); the security story ("nothing is downloaded or installed").
- **Harder:** anyone relying on removed pieces needs a migration note. Presets are renamed. `-IncludeOptional` goes (it can be accepted and ignored with a warning for one release).
- **Revisit:** a native Sysmon tier on Windows 11 / Server 2025 (built in, so no download) is the most likely next addition and should pass section 4 easily. Field-test the Intune pack in a real tenant before calling it production-ready.

## Action items

1. [ ] Merge #36 (transcription removal).
2. [x] Accept this ADR (Option B; WEF whole channels only, 3 role presets + ASD, ATT&CK report as a maintainer tool, Autoruns add-on deleted).
3. [ ] #38 Tiers: move Crypto-DPAPI debug and IPsec Driver to HighVolume; make `-IncludeOptional` accepted-but-ignored with a warning.
4. [ ] #39 Presets: generate 4 (`Workstation`, `MemberServer`, `DomainController`, `ASD`); delete the other 6; update docs and field-report template.
5. [ ] #53 Delete the Autoruns add-on: `addons/`, `docs/addons.md`, its self-check and fixture (history stays in git).
6. [ ] #40 Remove `report/Invoke-WELACheck.ps1`, `docs/extras/sentinel-kql.md`, `data/ossem/` (with the coverage report's `-UseOssem` mode).
7. [ ] #41 WEF: remove `-Filter Baseline`, `Test-WefFilter.ps1`, `tools/Update-AuditSubcategoryEvents.ps1`, `data/wef/` and `$BaselineWefSuppress` (added at the maintainer's request); add a short "filter at the SIEM ingest layer" note to Collect.
8. [ ] #42 Move `report/Export-AttackCoverage.ps1` to `tools/`; drop the empty `report/` folder.
9. [ ] #43 README: new one-sentence goal, the "pick a role preset" quick start, and a "not in scope" list.
10. [ ] #43 CHANGELOG (then tag **v2.0.0** after merge) with a migration table (old name, new name or replacement).
11. [x] Create GitHub issues for the ADR-001 roadmap items that still apply after this cut (#44 to #52; the WEF filter, Autoruns and Sentinel KQL items were dropped by this ADR).
12. [ ] #43 Add `docs/adr/0001-v1-layout.md` as a short record pointing at PR #30, so both ADRs live in the repo.
