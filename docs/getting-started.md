# Getting Started

Three commands get you from nothing to a verified logging baseline:
preview (`-WhatIf`), apply, test. Everything on this page fits in ten
minutes on one machine.

## The words we use

Eight terms cover the whole kit - each defined once, in plain English:

| Term | Meaning |
|---|---|
| Event channel | A named log Windows writes to (Security, System, ...) |
| Audit subcategory | A Windows switch deciding which security events get recorded |
| Tier | How much logging: **Core** (safe default), **HighVolume** (more events, more disk), **Optional** (situational) |
| Baseline / selection CSV | A spreadsheet listing which settings are on (Y) or off (N) - the kit's unit of decision |
| Preset | A ready-made baseline we ship (ASD, Microsoft, the `spydi_*` pairs) |
| WEF / collector | Windows' built-in way to push events to one central server, agent-free |
| SIEM | The security platform that ultimately analyses the logs (outside this kit) |
| ATT&CK technique | A catalogued attacker behaviour - the kit counts how many your logs could see |

*Plain-language shorthand; the formal definitions live in
[Microsoft's audit policy documentation](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
and [MITRE ATT&CK](https://attack.mitre.org/).*

## Requirements

- Windows Server 2019 / 2022 / 2025, or Windows 10 / 11
- PowerShell: [PowerShell 7](https://learn.microsoft.com/powershell/scripting/whats-new/migrating-from-windows-powershell-51-to-powershell-7)
  where installed, or the stock Windows PowerShell 5.1 that ships with
  every supported Windows version - both work, and CI tests both. 5.1 is
  the compatibility floor because it is always present (and
  [Intune remediations run under Windows PowerShell](https://learn.microsoft.com/intune/intune-service/fundamentals/remediations),
  so the generated packs must stay 5.1-clean), not a requirement to use
  it.
- Local Administrator for applying and verifying (the builders and
  generators need no elevation)
- No modules, no agents, no internet access required

## Install

Either grab the versioned zip (with SHA256 checksum) from the
[Releases page](https://github.com/spydisec/WinLogKit/releases), or clone:

```powershell
git clone https://github.com/spydisec/WinLogKit.git
cd WinLogKit
```

If a downloaded zip is blocked, unblock the files once:

```powershell
Get-ChildItem -Recurse | Unblock-File
```

## If scripts are blocked: "running scripts is disabled on this system"

PowerShell's execution policy blocks `.ps1` files by default on client
Windows (`Restricted`; servers default to `RemoteSigned` - see
[about_Execution_Policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies)).
Pick the least-invasive option that fits:

```powershell
# Option 1 - this window only, nothing persisted (recommended for a first look):
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned

# Option 2 - one-off invocation without touching any policy:
powershell.exe -ExecutionPolicy Bypass -File .\Enable-LoggingBaseline.ps1 -WhatIf

# Option 3 - persist for your user account:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Notes:

- Under `RemoteSigned`, files downloaded from the internet still carry the
  Mark of the Web and stay blocked until the `Unblock-File` step above -
  the two blockers look identical but have different fixes. `git clone`
  produces unmarked files, so cloning avoids that half entirely.
- If the error says the policy is **set by Group Policy**, your organisation
  enforces it and nothing local overrides it: `MachinePolicy` and
  `UserPolicy` sit above the Process scope that Options 1 and 2 use, per
  [about_Execution_Policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies).
  Have the scripts signed per your org's process, or ask for the policy to
  be changed. The Intune remediation pack is unaffected (Intune
  executes remediations with its own bypass), and none of this weakens
  anything the kit configures - execution policy is a usability guardrail,
  not a security boundary, per Microsoft's own documentation.

## First run - see everything before changing anything

From an **elevated** Windows PowerShell prompt in the kit folder:

```powershell
# Full diff of what would change. Nothing is changed.
.\Enable-LoggingBaseline.ps1 -WhatIf
```

## Apply and verify (the 10-minute path)

```powershell
# 1. Apply the Core tier. The first real run captures a rollback baseline
#    (audit policy backup, channel sizes, registry values) to .\Baseline\.
.\Enable-LoggingBaseline.ps1

# 2. Verify: per-category PASS/FAIL to console, evidence CSVs to .\Results\.
.\Test-LoggingBaseline.ps1

# 3. Decide on the high volume tier with evidence, then apply it.
.\Export-AttackCoverage.ps1                    # what Core makes observable
.\Export-AttackCoverage.ps1 -IncludeHighVolume # what HighVolume adds
.\Enable-LoggingBaseline.ps1 -IncludeHighVolume
.\Test-LoggingBaseline.ps1   -IncludeHighVolume

# 4. Independent second opinion (fetches WELA once, on request).
.\Invoke-WELACheck.ps1 -Download

# Escape hatch: restore everything captured at first run.
.\Enable-LoggingBaseline.ps1 -Rollback
```

`Test-LoggingBaseline.ps1` exits non-zero on any failure, so it can gate a
pipeline or an Intune/RMM check as-is.

## Build your own baseline instead

When you want per-setting control (or per-role baselines), build a selection
CSV first - the kit recommendation is shown per item, with the volume and
stability risk, and `t` shows the whole tree at any point:

```powershell
.\New-LoggingBaseline.ps1                       # interactive walk-through
.\New-LoggingBaseline.ps1 -Show                 # view the recommendation as a tree
.\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv -WhatIf
.\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv
.\Test-LoggingBaseline.ps1   -BaselineFile .\MyBaseline.csv
```

Or start from a published reference: see
[Baselines & Presets](baselines.md).

## Where things land

| Folder | Contents |
|---|---|
| `Baseline\` | First-run rollback capture (auditpol backup + JSON); `snapshots\<timestamp>\` holds an automatic pre-change snapshot from every later apply |
| `Results\` | Test and coverage CSVs, timestamped |
| `Logs\` | Enable transcripts (every run, including `-WhatIf`) |
| `Evidence\` | Raw WELA output per run, timestamped |
| `Intune\`, `WEF\`, `GPO\` | Generated deployment artefacts |

All of these are per-host output and gitignored - only the kit itself and
your baseline CSVs belong in version control.
