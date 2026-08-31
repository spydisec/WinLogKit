# Getting Started

## Requirements

- Windows Server 2019 / 2022 / 2025, or Windows 10 / 11
- Windows PowerShell 5.1 (stock - PowerShell 7 also works)
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
