# Baselines & Presets

A baseline is just a list of which settings are on. This page shows the
ready-made lists we ship, how to build your own, and which one to pick.
**In a hurry?** Use the preset for the host's role: `Workstation` for
Windows 10/11, `MemberServer` for servers, `DomainController` for domain
controllers.

## The model

The settings table (`WinLogKit.Settings.ps1`) is the single source of
truth: every channel, audit subcategory, registry value and SMB audit
setting, each with a plain-language purpose, a tier, a scope, behaviour
category tags and - where it matters - a volume/stability risk note.

Everything else is a **selection** of that table:

| Selection mechanism | When to use |
|---|---|
| A shipped preset (`presets\*.csv`) | Start here: one per host role, plus ASD |
| A selection CSV from `New-LoggingBaseline.ps1` | Per-setting control; review in Excel, keep in git |
| Tier switch (`-IncludeHighVolume`) | Quick tests without a CSV |

One selection drives everything: Enable, Test, the WEF
subscription, the GPO pack and the ATT&CK coverage report all accept the
same `-BaselineFile`. When a baseline file is given, tier switches are
ignored: the file is the decision.

## Tiers

| Tier | Default | Contents |
|---|---|---|
| Core | applied | everything with low or justified volume |
| HighVolume | ask first | process creation + command line, PowerShell script block + module logging (Windows PowerShell and PowerShell 7), WFP connections, sensitive privilege use, plus the situational Crypto-DPAPI debug channel and IPsec Driver auditing |

PowerShell transcription is deliberately not in the kit. It writes text
files outside the event log (its own folder, permissions, retention and
collection path), and script block logging (4104) already records the code
that ran. If you need transcripts, set them by GPO to a central
write-only share.

The split exists so volume decisions are made by a human with the impact in
front of them - `Export-AttackCoverage.ps1` quantifies what the HighVolume
tier buys (114 additional ATT&CK techniques over Core: 169 -> 283 of the
298-technique native ceiling; see [Coverage](mapping.md)).

## Role presets

The kit's recommended *starting point* per host role - Core plus the
high-value items that role can afford, with every hold-back justified by the
settings table's own Risk notes. These are starting points pending pilot
volume data, not final answers: run the pilot week, check the numbers, and
adjust your copy.

| Preset | Selection | Observable techniques |
|---|---|---|
| `Workstation.csv` | Core + process creation/cmdline + script block logging + WFP connections; DC-only items deselected | **269** of 472 mapped = 90% of the 298 native ceiling |
| `MemberServer.csv` | as Workstation, **without** WFP connections | **267** of 472 = 90% of ceiling |
| `DomainController.csv` | as MemberServer, plus the DC-scope subcategories | **277** of 472 = 93% of ceiling |

The reasoning per decision (volume and behaviour characterisations come from
the settings table's Risk notes, themselves sourced from
[Microsoft's advanced audit policy documentation](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
and the Yamato guide):

| Item | Wks | Member | DC | Why |
|---|---|---|---|---|
| Process creation + command line | ✓ | ✓ | ✓ | Highest single detection value; volume scales with process churn - watch RDS/build hosts in the pilot |
| Script block logging (4104), Windows PowerShell and PowerShell 7 | ✓ | ✓ | ✓ | Moderate volume, de-obfuscated code, generally safe fleet-wide per its Risk note |
| WFP connections (5156/5157) | ✓ | - | - | Client connection volume is modest; documented **High** volume on connection-heavy servers and DCs |
| Module logging (4103) | - | - | - | The heaviest setting in the kit; opt-in after a pilot, everywhere |
| Sensitive Privilege Use | - | - | - | Known to flood with backup agents; opt-in per server role after a pilot |
| DC-scope subcategories | - | - | ✓ | Only generate events on domain controllers |
| DPAPI debug channel, IPsec Driver | - | - | - | Situational: enable where DPAPI theft is monitored or IPsec is used |

Usage is identical to any baseline CSV:

```powershell
.\New-LoggingBaseline.ps1 -Show -BaselineFile .\presets\Workstation.csv
.\Enable-LoggingBaseline.ps1 -BaselineFile .\presets\MemberServer.csv -WhatIf
.\fleet\New-GpoPack.ps1 -BaselineFile .\presets\MemberServer.csv -OutDir .\GPO\MemberServer
```

To customise a role, copy the CSV, flip `Selected` values in Excel, and keep
your copy in version control - the shipped presets are regenerated from the
settings table and CI rejects drift, so edit copies, not the originals.
Selection CSVs carry item choices, not sizes: the Security log stays at the
kit's 1 GB (raise it in `WinLogKit.Settings.ps1` if you want more).

## Reference preset: ASD

`presets\ASD.csv` is the Australian Signals Directorate baseline (25 items),
expressed as a selection and faithful to the script in Yamato's
[EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide).
Use it to deploy or compare against ASD's published recommendation. The
Microsoft client and server recommendations are tracked too, but only to
fill the **Refs** column on the [Reference page](reference.md); they are
narrower than the kit's Core tier, so they don't ship as presets. All three
definitions live in `tools\reference-baselines.psd1`.

Faithfulness limits (stated, not hidden): the kit applies its own
Success/Failure flags and channel sizes, which superset the reference in
places (one exception: ASD sizes Security at 2 GB versus the kit's 1 GB);
five ASD subcategories cannot be expressed because Yamato's own baseline
excludes them (Process Termination, Group Membership, and the
SACL-dependent File System / Kernel Object / Registry). The ASD script only
sets the Windows PowerShell policies, so `ASD.csv` doesn't cover PowerShell 7;
flip the four `PS7*` rows to Y in your copy if you need it.

## Building your own

```powershell
.\New-LoggingBaseline.ps1
```

Walks every item: recommendation shown as the default (Enter accepts), risk
notes in yellow, `a` accepts defaults for the rest of a section, `t` shows
the **baseline tree** - every item's include/exclude state plus a
per-category coverage count, with uncovered categories in red. The output
CSV is plain text: flip `Selected` between Y/N in Excel, commit it per
server role, and you have reviewable, versioned logging baselines.

Audit any CSV later:

```powershell
.\New-LoggingBaseline.ps1 -Show -BaselineFile .\FileServerBaseline.csv
```

## Deviations from the Yamato sources

A handful of deliberate differences from the upstream scripts, each with a
reason. Everything else is faithful.

| Item | Yamato/WELA does | This kit does | Why |
|---|---|---|---|
| `RestrictSendingNTLMTraffic` | WELA configure sets **2 (Deny all)** | **1 (Audit all)** | 2 blocks outgoing NTLM, which is enforcement and can break connectivity. Logging change only. |
| `AuditNTLMInDomain` | WELA sets 2 | 7 (audit all, DC only) | 7 is Microsoft's documented "enable all" value for this setting. |
| PowerShell policy registry paths | Batch writes only `Wow6432Node` | Both native and `Wow6432Node` paths | Group Policy writes the native path; 64-bit PowerShell reads it. Both paths cover both host bitnesses. |
| PrintService/Operational | Batch sizes it but never enables it | Enabled | The log is disabled by default; sizing a disabled log records nothing. |
| AD CS AuditFilter | WELA restarts CertSvc automatically | Sets value, warns, never restarts | Service restarts belong in a change window, not a script side effect. |
| Other Policy Change Events | Guide text says leave off (5447 noise); both Yamato scripts enable it | Enabled (Core), noise note attached | Follows the scripts; drop it if 5447 floods after the pilot week. |
| `SCENoApplyLegacyAuditPolicy` (Audit: Force audit policy subcategory settings) | Not set | Set to 1 (Core) | Windows' default, set explicitly so Test catches a policy that turns it off; otherwise a legacy category-level audit policy silently overrides every subcategory setting. |

WELA's `configure` command is deliberately never called by the kit: it
prompts interactively, restarts CertSvc itself, and sets the NTLM deny
value. All changes go through `Enable-LoggingBaseline.ps1`.
