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

## v0.3 - Workstation profile (Windows 10 / 11)

- Client-OS settings table: defaults differ from Server (e.g. Credential
  Validation and Kerberos subcategories are No Auditing on client OS), and the
  Yamato guide's client recommendations differ in places from the server ones
- Role profiles in `LoggingBaseline.Settings.ps1` (Server / Workstation / DC)
  selected automatically from `Win32_OperatingSystem.ProductType` with an
  override switch
- **Intune delivery**: package Enable/Test as an Intune remediation pair
  (detection script = `Test-LoggingBaseline.ps1` logic, remediation script =
  `Enable-LoggingBaseline.ps1` logic), plus settings-catalog / CSP mappings
  where one exists (PowerShell logging and command line capture are
  ADMX-backed; audit policy needs the remediation route)

## v0.4 - GPO delivery for fleet scale

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
