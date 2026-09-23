# Get started

From nothing to a verified logging baseline on one machine in about ten
minutes: pick the preset for the host's role, preview, apply, verify.

## Requirements

- Windows 10 / 11, or Windows Server 2019 / 2022 / 2025
- PowerShell 7 or the Windows PowerShell 5.1 that ships with Windows (both
  are tested)
- Local Administrator to apply and verify (building a baseline or
  generating fleet files needs no elevation)
- No modules, no agents, no internet access

## Install

Download the zip (with its SHA256 checksum) from the
[Releases page](https://github.com/spydisec/WinLogKit/releases), or clone:

```powershell
git clone https://github.com/spydisec/WinLogKit.git
cd WinLogKit
```

A downloaded zip is marked as coming from the internet; unblock it once:

```powershell
Get-ChildItem -Recurse | Unblock-File
```

## If scripts are blocked: "running scripts is disabled on this system"

Allow scripts for the current window only; nothing is saved:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
```

??? note "Other options, and policies set by Group Policy"
    - One-off run without touching any policy:
      `powershell.exe -ExecutionPolicy Bypass -File .\Enable-LoggingBaseline.ps1 -WhatIf`
    - Keep it for your user account:
      `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`
    - Under `RemoteSigned`, downloaded files stay blocked until the
      `Unblock-File` step above. The two errors look the same but have
      different fixes; `git clone` avoids the download one.
    - If the error says the policy is **set by Group Policy**, nothing local
      overrides it (`MachinePolicy` and `UserPolicy` sit above the Process
      scope, per
      [about_Execution_Policies](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies)).
      Have the scripts signed, or ask for the policy to change. The Intune
      Settings catalog and the GPO pack's policy settings run no kit
      scripts on the endpoints, so they aren't affected; a startup script
      you add for the other log sizes is, like any script.
    - Execution policy is a usability guardrail, not a security boundary;
      none of this weakens anything the kit configures.

## Your first baseline

From an **elevated** PowerShell prompt in the kit folder, choose the preset
for the host's role: `Workstation` (Windows 10/11), `MemberServer` or
`DomainController` (see [Baselines](baselines.md#role-presets)).

```powershell
$preset = '.\presets\Workstation.csv'

# 1. Preview: the full list of changes. Nothing is changed.
.\Enable-LoggingBaseline.ps1 -BaselineFile $preset -WhatIf

# 2. Apply. The first real run saves a rollback copy of the current
#    settings to .\Baseline\ before changing anything.
.\Enable-LoggingBaseline.ps1 -BaselineFile $preset

# 3. Verify: PASS/FAIL per behaviour category, evidence CSVs in .\Results\.
.\Test-LoggingBaseline.ps1 -BaselineFile $preset

# Undo everything, back to the state saved at step 2.
.\Enable-LoggingBaseline.ps1 -Rollback
```

`Test-LoggingBaseline.ps1` exits non-zero on any failure, so it can gate a
pipeline or an Intune/RMM check as-is.

## Next steps

1. **Pilot for a week** on a machine that mirrors production, and watch
   disk and event volume ([Safety](safety.md#volume-impact-settings-the-highvolume-tier-and-friends)).
2. **Adjust your copy of the preset.** The HighVolume rows it leaves off
   (module logging, sensitive privilege use and so on) are the next
   decisions; [Coverage](mapping.md) shows what they add. To build a
   selection from scratch instead, run `.\New-LoggingBaseline.ps1`
   ([Baselines](baselines.md#building-your-own)).
3. **Roll it out** with Intune or Group Policy ([Deploy](deployment.md)).
4. **Collect it centrally**, if you use Windows Event Forwarding
   ([Collect](wec.md)).

## Where things land

| Folder | Contents |
|---|---|
| `Baseline\` | The rollback copy from the first run; `snapshots\<timestamp>\` holds a copy from before every later run |
| `Results\` | Test and coverage CSVs, timestamped |
| `Logs\` | A log of every Enable run, including `-WhatIf` |
| `WEF\`, `GPO\` | Generated deployment files |

These are per-host output and git-ignored; only the kit and your own
baseline CSVs belong in version control.

## The words we use

| Term | Meaning |
|---|---|
| Event channel | A named log Windows writes to (Security, System, ...) |
| Audit subcategory | A Windows switch deciding which security events get recorded |
| Tier | How much logging: **Core** (safe default) or **HighVolume** (more events and disk, or only useful in some environments) |
| Baseline / selection CSV | A spreadsheet listing which settings are on (Y) or off (N) |
| Preset | A ready-made baseline: one per host role, plus `ASD` |
| WEF / collector | Windows' built-in way to push events to one central server, agent-free |
| SIEM | The security platform that analyses the logs (outside this kit) |
| ATT&CK technique | A catalogued attacker behaviour; the kit counts how many your logs could see |
