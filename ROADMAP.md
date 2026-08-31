# Roadmap

## v0.2.0 (current)

- Windows Server 2019 / 2022 / 2025, standalone and domain joined (Server 2025
  SMB signing/encryption auditing included, OS-gated)
- Enable / test / rollback via local PowerShell 5.1, tiered (Core, HighVolume, Optional)
- Interactive baseline builder (`New-LoggingBaseline.ps1`): per-setting selection
  with the kit recommendation and risk notes shown, Excel-editable CSV output
  consumed by enable and test via `-BaselineFile`
- Independent verification via WELA with archived evidence
- SDLC: branch + PR flow, CI (lint on PSScriptAnalyzer, self-checks on PS 5.1
  and PS 7, DevSkim security scan), Dependabot, tagged zip releases with
  SHA256 checksums

## v0.3 - Workstation profile and Intune delivery (in progress)

- [x] Kit verified applicable to client Windows: host profile detection
  (workstation / server / DC), runtime NOT APPLICABLE gating, README guidance
- [x] **Intune delivery**: `New-IntuneRemediationPack.ps1` compiles the
  settings table (or a baseline CSV) into a self-contained detection +
  remediation pair (SYSTEM, 64-bit, exit-code contract)
- [x] IPsec Driver subcategory added (Optional) from
  [Microsoft's baseline recommendation](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations)
  via Yamato's [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide)
  comparison
- [ ] Field-test the pack in a real Intune tenant (assignment, schedule,
  reporting) and fold back findings
- [ ] Settings-catalog / CSP mappings where they exist (PowerShell logging and
  command line capture are ADMX-backed, and audit subcategories are exposed via
  the [Policy CSP - Audit](https://learn.microsoft.com/windows/client-management/mdm/policy-csp-audit);
  the kit does not map these yet - the shipped route today is the remediation
  pack, which also covers channel sizing that has no CSP)
- [ ] Per-role recommended CSVs shipped in the repo (workstation / member
  server / DC) once volume data from pilots justifies the defaults

## v0.4 - Fleet collection and reference baselines (in progress)

- [x] **WEF/WEC**: `New-WefSubscription.ps1` generates a source-initiated
  subscription XML from the settings table or any baseline CSV, with
  collector/source setup guidance (generate -> transport -> ingest boundary
  documented; SIEM ingestion stays out of scope)
- [x] **Reference presets**: `presets/` ships ASD, Microsoft_Client and
  Microsoft_Server as selection CSVs, faithful to Yamato's
  EventLog-Baseline-Guide scripts, drift-checked in CI against
  `tools/New-PresetBaselines.ps1`
- [ ] Collector-side checks (SubscriptionManager policy and WinRM state on
  sources, ForwardedEvents sizing) in Test-LoggingBaseline
- [ ] Remaining GPO items below

### GPO delivery for fleet scale

- Generate a GPO-importable advanced audit policy `audit.csv` directly from
  the settings table, so the GPO can never drift from the tested baseline
- Mapping table: every subcategory and registry value to its Group Policy
  path (Advanced Audit Policy Configuration / Administrative Templates)
- LGPO.exe backup/import artefacts for air-gapped estates
- Channel sizing at scale (the awkward one: non-classic channel sizes have no
  clean ADMX, so document the startup-script and registry `MaxSize` options
  with their caveats)
- Domain controller profile notes (volume expectations for DS Access, SAM,
  Kerberos subcategories on real DCs)

## Later / help wanted

- Locale-independent verification: parse numeric setting values from
  `auditpol /backup` output instead of localised `auditpol /get /r` text
- Pester-based test suite (CI with PSScriptAnalyzer + self-checks on 5.1 and 7
  shipped in v0.2.0; migrating the harness to Pester remains)
- Event volume telemetry: a companion script that measures events/hour per
  setting after the pilot week, to make the HighVolume decision evidence-based
- Optional Windows Event Forwarding (WEC/WEF) subscription templates for the
  agentless collection path
