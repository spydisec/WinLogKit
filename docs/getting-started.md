# Getting Started

## Requirements

- Windows Server 2019 / 2022 / 2025, or Windows 10 / 11
- Windows PowerShell 5.1 (stock; the kit targets 5.1 - CI additionally
  parses everything and runs the builders/generators under PowerShell 7)
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
  enforces it: use Option 2 per invocation, or have the scripts signed per
  your org's process. The Intune remediation pack is unaffected (Intune
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
| `Baseline\` | First-run rollback capture (auditpol backup + JSON) |
| `Results\` | Test and coverage CSVs, timestamped |
| `Logs\` | Enable transcripts (every run, including `-WhatIf`) |
| `Evidence\` | Raw WELA output per run, timestamped |
| `Intune\`, `WEF\`, `GPO\` | Generated deployment artefacts |

All of these are per-host output and gitignored - only the kit itself and
your baseline CSVs belong in version control.
