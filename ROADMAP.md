# Roadmap

## v0.1.0 (current)

- Windows Server 2019 / 2022, standalone and domain joined
- Enable / test / rollback via local PowerShell 5.1, tiered (Core, HighVolume, Optional)
- Independent verification via WELA with archived evidence

## v0.2 - Workstation profile (Windows 10 / 11)

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

## v0.3 - GPO delivery for fleet scale

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
- Pester test suite and CI (PSScriptAnalyzer + parse checks on 5.1 and 7)
- Event volume telemetry: a companion script that measures events/hour per
  setting after the pilot week, to make the HighVolume decision evidence-based
- Optional Windows Event Forwarding (WEC/WEF) subscription templates for the
  agentless collection path
