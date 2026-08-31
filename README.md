# WinLogKit

[![CI](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml/badge.svg)](https://github.com/spydisec/WinLogKit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/spydisec/WinLogKit?include_prereleases)](https://github.com/spydisec/WinLogKit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**An easy, auditable way to implement the
[Yamato Security](https://github.com/Yamato-Security) Windows event logging
baselines with native PowerShell.** Enable the right event channels, advanced
audit policy subcategories and registry settings; verify them repeatably; and
get an independent second opinion from
[WELA](https://github.com/Yamato-Security/WELA) - all with plain Windows
PowerShell 5.1, no modules, no agents.

Targets **Windows Server 2019 / 2022 / 2025 and Windows 10 / 11 workstations**,
standalone or domain joined. Version-specific items (the Server 2025 / Win11
24H2 SMB signing/encryption auditing) and role-specific items (domain
controller subcategories) are detected at runtime and reported NOT APPLICABLE
where they don't apply. Fleet delivery to workstations via **Intune
remediations** (`New-IntuneRemediationPack.ps1`), central collection via
**WEF/WEC subscriptions** (`New-WefSubscription.ps1`) and **GPO artefacts**
(`New-GpoPack.ps1`) are built in, and `Export-AttackCoverage.ps1` reports
which MITRE ATT&CK techniques a selection makes observable (via
[OSSEM-DM](https://github.com/OTRF/OSSEM-DM)). Versioned releases with
zip + SHA256 artefacts are on the
[Releases page](https://github.com/spydisec/WinLogKit/releases); see
[CHANGELOG.md](CHANGELOG.md) for what each version added.

**Full documentation**: <https://spydisec.github.io/WinLogKit/>

**Scope**: native Windows configuration only. No Sysmon, no Sysinternals, no
third party agents. Where a behaviour category cannot be fully satisfied
natively, the docs say so instead of pretending.

## Credits

The settings themselves come from Yamato Security's excellent work:

- [EnableWindowsLogSettings](https://github.com/Yamato-Security/EnableWindowsLogSettings) -
  the configuration guide and batch script this kit operationalises
- [WELA](https://github.com/Yamato-Security/WELA) v2.1.0 - used here as an
  independent verification tool
- [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide) -
  Yamato's comparison app for the Windows Default / YamatoSecurity / ASD /
  Microsoft Client / Microsoft Server baselines with Sigma detection coverage
  impact. Useful for justifying the baseline choice: the YamatoSecurity set
  this kit implements is the broadest of the four, and the Microsoft Client
  baseline is a strict subset of it, so workstations running this kit exceed
  Microsoft's client recommendation.

This project is not affiliated with or endorsed by Yamato Security. A handful
of deliberate deviations from their scripts are documented below, with reasons.

## ⚠️ Warning

Same warning as the upstream guide: understand and **test every setting on a
non-production machine that mirrors your environment for at least a week**
before rolling out. Logging volume is real money and real disk. Use at your
own risk.

---

## Files

| File | What it does |
|---|---|
| `LoggingBaseline.Settings.ps1` | The single source of truth: every channel, audit subcategory and registry value, with tier, scope, category tags, a plain-language purpose and (where it matters) a volume/stability risk note per setting. The scripts below dot-source it, so enable and verify can never drift apart. Change settings **here**, not in the scripts. |
| `New-LoggingBaseline.ps1` | Interactive baseline builder. Walks every setting, shows the kit recommendation and the risk note, and writes your selections to a CSV (`MyBaseline.csv`). Changes nothing; needs no admin. The CSV is Excel-editable and feeds the two scripts below via `-BaselineFile`. |
| `Enable-LoggingBaseline.ps1` | Applies the baseline. Idempotent, reports changed vs already-correct, `-WhatIf` for a full diff, `-Rollback` to restore first-run state, never reboots, flags high volume settings for a human decision. Writes a transcript to `.\Logs\`. |
| `Test-LoggingBaseline.ps1` | Verification only, changes nothing. Per-category PASS / FAIL / NOT APPLICABLE to console, detail + summary CSVs to `.\Results\`, non-zero exit code on any failure so it can gate a pipeline. |
| `Invoke-WELACheck.ps1` | Locates (or with `-Download` fetches) WELA, runs `audit-settings` and `audit-filesize`, parses the CSVs, reports deviations, archives raw output with a timestamp under `.\Evidence\`. |
| `New-IntuneRemediationPack.ps1` | Compiles the settings table (optionally filtered by a baseline CSV) into a self-contained Intune remediation pair: `Detect-LoggingBaseline.ps1` (exit 0/1) and `Remediate-LoggingBaseline.ps1`. No admin needed to generate; the pack embeds everything, so endpoints need nothing but the two uploaded scripts. |
| `New-WefSubscription.ps1` | Generates a source-initiated WEF subscription XML from the settings table or a baseline CSV, so the channels the kit enables can be collected centrally on a Windows Event Collector. Prints the collector (`winrm qc`, `wecutil`) and source (GPO SubscriptionManager) setup steps. Verify either side with `Test-LoggingBaseline.ps1 -WefRole Source` or `-WefRole Collector`. |
| `New-GpoPack.ps1` | Generates GPO delivery artefacts from a selection: the advanced audit policy `audit.csv` (GUID-driven) and an LGPO-format `registry.txt` for the policy registry values, plus reminders for what GPO deliberately can't carry. |
| `Export-AttackCoverage.ps1` | Reports which MITRE ATT&CK techniques a selection makes observable, and why the rest are not (deselected / excluded by design / Sysmon-only), by joining the vendored [OSSEM-DM](https://github.com/OTRF/OSSEM-DM) snapshot in `data/ossem/`. Core = 152 of 362 mapped Windows techniques; +HighVolume = 320 (the HighVolume tier is where most observability lives). |
| `presets/` | Selection CSVs usable anywhere a `-BaselineFile` is accepted: reference baselines (`ASD.csv`, `Microsoft_Client.csv`, `Microsoft_Server.csv`) and per-role starting points (`role_Workstation.csv` 317/362 ATT&CK techniques, `role_MemberServer.csv` 299, `role_DomainController.csv` 302 - rationale in the docs). Regenerated by `tools/New-PresetBaselines.ps1`; CI fails if they drift from the settings table. |
| `tests/Invoke-KitChecks.ps1` | Self-checks (parse, settings consistency, builder round-trip, Intune pack, preset drift, WEF XML). Safe anywhere, no admin. CI runs it on Windows PowerShell 5.1 and PowerShell 7; run it locally before a PR. |

## Quick start

All commands from an elevated Windows PowerShell 5.1 prompt, in the kit folder
(`New-LoggingBaseline.ps1` is the one script that does not need elevation).
If you hit "running scripts is disabled on this system", see
[Getting Started](https://spydisec.github.io/WinLogKit/getting-started/#if-scripts-are-blocked-running-scripts-is-disabled-on-this-system)
- `Set-ExecutionPolicy -Scope Process RemoteSigned` unblocks the current
window without persisting anything.

There are two ways to drive the kit. **Path A** uses the tier switches and is
the fastest route to the recommended baseline. **Path B** builds a custom
baseline file first - pick that when you want to decide setting-by-setting
(with the kit recommendation shown as a reference), or when different server
roles need different selections.

### Path A - tier switches

```powershell
# 1. See the full diff. Nothing is changed.
.\Enable-LoggingBaseline.ps1 -WhatIf

# 2. Apply the Core tier. First real run also captures the rollback baseline
#    (audit policy backup, channel sizes, registry values) to .\Baseline\.
.\Enable-LoggingBaseline.ps1

# 3. Review the PENDING DECISION list and the volume table below, then apply
#    the high volume tier if the volume is accepted.
.\Enable-LoggingBaseline.ps1 -IncludeHighVolume

# 4. Verify (assessing the same tiers you applied).
.\Test-LoggingBaseline.ps1 -IncludeHighVolume

# 5. Independent second opinion with WELA, evidence archived per run.
.\Invoke-WELACheck.ps1 -Download          # first run on an internet-connected box
.\Invoke-WELACheck.ps1                    # thereafter

# If needed: put everything back the way it was before the first run.
.\Enable-LoggingBaseline.ps1 -Rollback
```

### Path B - build your own baseline (recommendation as reference)

```powershell
# 1. Walk through every setting interactively. Each item shows the kit
#    recommendation (Enter accepts it) and its volume/stability risk, so
#    heavy settings are chosen with eyes open. Writes MyBaseline.csv.
.\New-LoggingBaseline.ps1

#    ...or skip the prompts: write the recommended set to CSV and edit it
#    in Excel instead (flip the Selected column between Y and N).
.\New-LoggingBaseline.ps1 -AcceptRecommended -OutFile .\FileServerBaseline.csv

# 2. Preview, apply, verify - all driven by the same file, so what you
#    test is exactly what you selected.
.\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv -WhatIf
.\Enable-LoggingBaseline.ps1 -BaselineFile .\MyBaseline.csv
.\Test-LoggingBaseline.ps1   -BaselineFile .\MyBaseline.csv
```

During the walk-through, press `t` at any prompt to see the **baseline tree**:
every item's current include/exclude state ( `?` marks not-yet-confirmed
defaults) plus a per-behaviour-category coverage count, so you always know
what the baseline contains so far. The same view works standalone:

```powershell
# What does the recommendation include?
.\New-LoggingBaseline.ps1 -Show

# What exactly is inside an existing baseline, and which categories does it cover?
.\New-LoggingBaseline.ps1 -Show -BaselineFile .\MyBaseline.csv
```

The baseline CSV is plain text - commit it per server role (file server,
web, DC) and you get reviewable, versioned logging baselines for free.
When `-BaselineFile` is used the tier switches are ignored; the file is the
decision. Rollback works the same in both paths.

Notes:

- **No reboot is required by anything in this kit.** The single conditional item
  (AD CS `AuditFilter`, only when Certificate Services is installed) needs a
  **CertSvc service restart**; the script sets the value, warns, and never
  restarts anything itself.
- On a **standalone server**, domain-controller-only items report
  NOT APPLICABLE and are skipped. Nothing depends on a domain being present.
- On **domain-joined** hosts, Group Policy reapplies audit policy at refresh.
  Local `auditpol` settings hold only until a GPO that configures audit policy
  overrides them, so for production fleets treat this kit as the
  **specification and verification**; deliver through GPO/Intune using the same
  values (native delivery artefacts are on the [roadmap](ROADMAP.md)).
  `Test-LoggingBaseline.ps1` and WELA verify the *effective* state either way.
- WELA's `configure` command is deliberately never called: it prompts
  interactively, restarts CertSvc itself, and sets
  `RestrictSendingNTLMTraffic=2` which **blocks** outgoing NTLM (see deviations
  below). All changes go through `Enable-LoggingBaseline.ps1`.

## Tiers

| Tier | Applied when | Contents |
|---|---|---|
| Core | always | Everything with low or justified volume |
| HighVolume | `-IncludeHighVolume` | Process Creation + command line, PowerShell script block + module logging, Filtering Platform Connection, Sensitive Privilege Use |
| Optional | `-IncludeOptional` | PowerShell transcription (set an output directory for your environment), Crypto-DPAPI debug channel, IPsec Driver auditing |

---

## Workstations (Windows 10 / 11)

The kit runs unchanged on client Windows - the scripts detect the host profile
(workstation / server / domain controller) and skip what doesn't apply:

- DC-only subcategories report NOT APPLICABLE; channels for absent features
  (e.g. AppLocker logs on unmanaged editions) report NOT APPLICABLE rather
  than failing.
- On Windows 11 24H2+ the SMB audit items apply just like Server 2025
  (per Microsoft's [SMB feature availability](https://learn.microsoft.com/windows-server/storage/file-server/smb-feature-descriptions));
  earlier builds report them NOT APPLICABLE.
- **Home edition**: no Group Policy, but everything this kit uses (`auditpol`,
  `wevtutil`, registry) works locally. Note that on any *domain-joined* device
  a logging GPO/Intune policy can override local settings at refresh - same
  caveat as servers.
- Volume calibration differs: workstations see far fewer logons/connections
  than servers, so the HighVolume tier is usually more affordable per host,
  while disk headroom (1 GB Security log) matters more on small SSDs.

Per Yamato's [EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide),
Microsoft's client baseline is a strict subset of the set this kit applies,
so client coverage meets-and-exceeds that reference.

## Reference baseline presets

The kit's settings table is the Yamato superset; every other published
baseline is a *selection* of it. `presets/` ships three, faithful to the
scripts in Yamato's
[EventLog-Baseline-Guide](https://github.com/Yamato-Security/EventLog-Baseline-Guide):

```powershell
.\New-LoggingBaseline.ps1 -Show -BaselineFile .\presets\ASD.csv    # audit what it includes
.\Enable-LoggingBaseline.ps1 -BaselineFile .\presets\ASD.csv -WhatIf
.\Test-LoggingBaseline.ps1   -BaselineFile .\presets\Microsoft_Server.csv
```

Faithfulness notes: the kit applies its own Success/Failure flags and channel
sizes, which superset these baselines in places (one exception: ASD sizes the
Security log at 2 GB where the kit uses 1 GB). Five ASD subcategories cannot
be expressed because they are not in the kit's table (Process Termination,
Group Membership, and the SACL-dependent File System / Kernel Object /
Registry) - the same items Yamato's own baseline leaves off. The Microsoft
presets configure no channels at all (their source scripts don't); flip
channel rows to Y in Excel if you want sizing with them. WELA's matching
`-Baseline` names (`ASD`, `Microsoft_Client`, `Microsoft_Server`) act as the
independent verifier for these presets.

## WEF/WEC central collection

Hosts *generate* events (this kit's job); WEF/WEC *transports* selected
events to a collector's ForwardedEvents log - natively and agentlessly; your
SIEM *ingests* from the collector (out of kit scope, deliberately).
`New-WefSubscription.ps1` generates the subscription from the same source of
truth as everything else:

```powershell
.\New-WefSubscription.ps1                                    # Core-tier channels
.\New-WefSubscription.ps1 -BaselineFile .\MyBaseline.csv     # exactly your selection
```

The generated subscription forwards whole channels: your baseline selection
is the coarse filter, and per-event XPath tuning is an operator step after
observing real volume - Microsoft's
[WEF intrusion-detection guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
has curated queries to graduate to. The script prints the collector
(`wecutil qc`, `wecutil cs`) and source (GPO SubscriptionManager) setup, and
the one classic trap: sources need NETWORK SERVICE in **Event Log Readers**
or Security-log forwarding silently fails. Size ForwardedEvents on the
collector like any busy log.

## Intune delivery

`New-IntuneRemediationPack.ps1` turns the settings table (or any baseline CSV
you built) into a standalone detection + remediation script pair for Intune:

```powershell
# Recommended (Core) pack:
.\New-IntuneRemediationPack.ps1

# Role-specific pack from a curated baseline:
.\New-LoggingBaseline.ps1 -AcceptRecommended -OutFile .\WorkstationBaseline.csv
.\New-IntuneRemediationPack.ps1 -BaselineFile .\WorkstationBaseline.csv -OutDir .\Intune\Workstation
```

Upload both files under **Devices > Manage devices > Scripts and remediations > Create**:
run using logged-on credentials **No** (SYSTEM), run in 64-bit PowerShell
**Yes**. Detection exits 0 when compliant and 1 with a one-line drift summary
otherwise; remediation applies only what is below baseline (idempotent, never
shrinks logs, never restarts anything - the AD CS AuditFilter is excluded
from packs for exactly that reason). Remediation also corrects "do not
overwrite" retention back to circular, matching the kit's never-do list.
Regenerate the pack whenever the settings table or your baseline CSV changes;
the generated files say not to edit them by hand. Like the kit's own
verification, the generated audit policy checks assume an English-language OS
(auditpol output is localised); on non-English endpoints detection may
re-trigger remediation each schedule, which is idempotent but noisy.

## Windows Server 2025 notes

- **New SMB auditing, included**: Server 2025 can audit which SMB peers cannot
  do signing or encryption (`Set-SmbServerConfiguration
  -AuditClientDoesNotSupportEncryption/Signing`, client-side equivalents;
  events 3021/3022 in `SMBServer/Audit`, 31998/31999 in `SmbClient/Audit`).
  The kit enables these (audit-only) and sizes both Audit channels. On
  2019/2022 the properties do not exist and the items report NOT APPLICABLE.
- **NTLM**: NTLMv1 is removed in Server 2025 and the SMB client supports NTLM
  blocking. The kit's NTLM values stay audit-only (`RestrictSendingNTLMTraffic
  = 1`), so they are safe on all supported versions and feed the evidence you
  need before turning any blocking on.
- **Alignment**: Microsoft's own Server 2025 security baseline (OSConfig)
  audits Success and Failure on nearly all subcategories, captures 4688 command
  lines, and requires the Security log at 192 MB minimum - this kit meets or
  exceeds all of that (Security at 1 GB).

## Stability safety: what this kit will never do

Windows auditing has a handful of settings that can genuinely hang, halt or
lock out a server. The kit never touches them, in either path:

| Never touched | Why it is dangerous |
|---|---|
| `CrashOnAuditFail` ("Audit: Shut down system immediately if unable to log security audits") | When enabled, a full Security log **halts the machine** with `STOP C0000244 {Audit Failed}`; until an admin clears the log and resets the value, only Administrators can log on - IIS returns 401/500s, AD replication fails with access denied. [Microsoft KB832981](https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/users-cannot-access-web-sites-when-log-full) |
| "Do not overwrite events" retention | Logging silently stops when the log fills; combined with `CrashOnAuditFail` it crashes the host. `Test-LoggingBaseline.ps1` flags this mode as a **FAIL** wherever it finds it. |
| "Audit the access of global system objects" / Global Object Access Auditing | Puts SACLs on every kernel/file/registry object - extreme event volume and measurable performance degradation; Microsoft describes it as too noisy for production. |
| Blanket File System / Registry SACLs | Per-object auditing volume depends entirely on the SACLs; a careless wildcard SACL can bury a file server. Scoping SACLs is a design decision, never a default. |
| Shrinking logs, rebooting, restarting services | The enable script only ever raises sizes, warns where a CertSvc restart is needed, and leaves the restart to a change window. |

The settings that are merely *heavy* (rather than dangerous) carry a `Risk`
note in `LoggingBaseline.Settings.ps1`, shown by the interactive builder and
summarised in the volume table below - the worst offenders are PowerShell
module logging (measurable PowerShell execution overhead on script-heavy
servers) and Filtering Platform Connection (Microsoft rates its volume High;
it can dominate the Security log on connection-heavy hosts).

## Category mapping

The kit organises settings by **behaviour category** rather than by channel, so
you can trace a monitoring requirement ("we must see scheduled task abuse") to
the exact settings that satisfy it. "Subcategory" = advanced audit policy
subcategory (Security log). DC = generated on domain controllers only.
HV = HighVolume tier.

| Category | Audit subcategories | Channels | Registry | Coverage |
|---|---|---|---|---|
| Authentication | Credential Validation; Logon; Logoff; Account Lockout; Other Logon/Logoff; Special Logon; Kerberos Authentication Service (DC); Kerberos Service Ticket Operations (DC) | Security; Microsoft-Windows-NTLM/Operational | MSV1_0 `RestrictSendingNTLMTraffic=1` (audit), `AuditReceivingNTLMTraffic=2`; Netlogon `AuditNTLMInDomain=7` (DC) | Full |
| Execution | Process Creation (HV) | Security; WMI-Activity/Operational; Bits-Client/Operational; AppLocker x4; Diagnosis-Scripted/Operational | `ProcessCreationIncludeCmdLine_Enabled=1` (HV) | Full via 4688+cmdline; no file hashes or DLL loads natively (accepted gap) |
| Account and access change | User Account Management; Security Group Management; Other Account Management; Computer Account Management (DC); Distribution Group Management (DC); Authentication Policy Change | Security | – | Full |
| Privilege use | Special Logon (4672); Sensitive Privilege Use (HV) | Security | – | Full |
| Logging tampered with | Audit Policy Change (4719); Security State Change; System Integrity; Other System Events (failure) | Security (1100/1102/1104 default); System (104); Defender/Operational (tamper) | – | Full |
| Software and service install | Security System Extension (4697) | System (7045); Application (MsiInstaller); CodeIntegrity/Operational; PrintService Admin + Operational | – | Full |
| Remote access | Logon (types 3/10); Other Logon/Logoff (4778/4779); RPC Events | TerminalServices-LocalSessionManager/Operational; SmbClient/Security | – | Full |
| Scheduled and automated tasks | Other Object Access (4698-4702) | TaskScheduler/Operational; WMI-Activity/Operational | – | Full |
| Scripting and command line | Process Creation (HV) | PowerShell/Operational (4103/4104); Windows PowerShell; PowerShellCore/Operational; Diagnosis-Scripted | Script block + module logging (HV); cmdline (HV); transcription (Optional) | Full for PowerShell; other interpreters visible only via 4688 command lines |
| Persistence | Security System Extension; Other Object Access; Directory Service Changes (DC) | System (7045); TaskScheduler; WMI-Activity; Bits-Client | – | **Partial**: registry autoruns (Run keys, IFEO) need the Registry subcategory + per-key SACLs, not in this baseline |
| Removable and external devices | Plug and Play (6416); Removable Storage (4663) | DriverFrameworks-UserMode/Operational | – | Full |
| Blocked and denied activity | Account Lockout; Filtering Platform Connection blocks (HV) | Defender/Operational; AppLocker x4; CodeIntegrity; Security-Mitigations x2; Firewall | – | Full (AppLocker channels populate only if AppLocker policy deployed) |
| Directory and identity store | Directory Service Access (DC); Directory Service Changes (DC); SAM; Kerberos Authentication Service (DC) | Security | – | Full on DCs; standalone = local SAM only (by design) |
| File and object access | File Share (5140/5142-5144); Removable Storage | Security | – | **Partial**: per-file auditing (4663) needs File System subcategory + SACLs on chosen paths, a per-asset design decision, deliberately not blanket-enabled |
| Certificates and keys | Certification Services (4898/4899); Other Policy Change (CNG) | Security; Crypto-DPAPI/Debug (Optional) | AD CS `AuditFilter=127` (only when AD CS installed; CertSvc restart) | Full where AD CS present; limited elsewhere (accepted) |
| Network flow and sessions | Filtering Platform Connection 5156/5157 (HV); RPC Events | Firewall channel; SmbClient/Security | – | **Partial**: no byte counts / flow aggregation natively; true flow telemetry needs network-layer sources, outside host scope |

### Categories not fully satisfiable natively (summary)

- **Persistence** (registry autorun keys), **File and object access** (per-file
  SACLs are a design decision, not a default), **Network flow and sessions**
  (no flow statistics), and **Execution/Scripting** depth (no hashes, module
  loads, or non-PowerShell script content). These are the recognised gaps of
  agentless native logging; do not expect a setting to close them.

---

## Settings inventory (from the Yamato sources)

### Channels: default vs target size

| Channel | Default | Target | Enable? |
|---|---|---|---|
| Security | 20 MB | 1 GB | already on |
| Microsoft-Windows-PowerShell/Operational | 15 MB | 1 GB | already on |
| Windows PowerShell | 15 MB | 1 GB | already on |
| PowerShellCore/Operational (if PS7 present) | 15 MB | 1 GB | already on |
| System / Application | 20 MB | 128 MB | already on |
| Defender, Bits-Client, Firewall, NTLM, Security-Mitigations x2, PrintService Admin, SmbClient (8 MB), AppLocker x4, CodeIntegrity, Diagnosis-Scripted, WMI-Activity, TS-LocalSessionManager | 1 MB | 128 MB | already on |
| **PrintService/Operational** | 1 MB | 128 MB | **must enable** (off by default) |
| **TaskScheduler/Operational** | 1 MB | 128 MB | **must enable** (off by default) |
| **DriverFrameworks-UserMode/Operational** | 1 MB | 128 MB | **must enable** (off by default) |
| Crypto-DPAPI/Debug (Optional tier) | 1 MB | 128 MB | must enable |

### Audit subcategories

All set to Success and Failure except **Other System Events** (Failure only,
per the Yamato batch). DC-only: Kerberos AS, Kerberos STO, Computer Account
Management, Distribution Group Management, Directory Service Access, Directory
Service Changes. Deliberately excluded, matching the Yamato batch: Process
Termination, Token Right Adjusted, Group Membership, Detailed File Share, File
System, Kernel Object, Registry, Filtering Platform Packet Drop, Authorization
Policy Change, Filtering Platform Policy Change, MPSSVC Rule-Level Policy
Change, Non-Sensitive Privilege Use.

### Registry settings

See `LoggingBaseline.Settings.ps1` for the full commented list: PowerShell
script block / module / transcription policies (both native and Wow6432Node
paths), process command line capture, NTLM auditing, AD CS AuditFilter.

### Deviations from the Yamato sources (deliberate, with reasons)

| Item | Yamato/WELA does | This kit does | Why |
|---|---|---|---|
| `RestrictSendingNTLMTraffic` | WELA configure sets **2 (Deny all)** | **1 (Audit all)** | 2 blocks outgoing NTLM, which is enforcement and can break connectivity. Logging change only. |
| `AuditNTLMInDomain` | WELA sets 2 | 7 (audit all, DC only) | 7 is Microsoft's documented "enable all" value for this setting. |
| PowerShell policy registry paths | Batch writes only `Wow6432Node` | Both native and `Wow6432Node` paths | Group Policy writes the native path; 64-bit PowerShell reads it. Both paths cover both host bitnesses. |
| PrintService/Operational | Batch sizes it but never enables it | Enabled | The log is disabled by default; sizing a disabled log records nothing. |
| AD CS AuditFilter | WELA restarts CertSvc automatically | Sets value, warns, never restarts | Service restarts belong in a change window, not a script side effect. |
| Other Policy Change Events | Guide text says leave off (5447 noise); both Yamato scripts enable it | Enabled (Core), noise note attached | Follows the scripts; drop it if 5447 floods after the pilot week. |

---

## Volume and performance impact

Settings with material volume, cost or privacy impact. These are exactly the
HighVolume/Optional tier plus the Core items worth watching in the pilot.

| Setting | Impact |
|---|---|
| Process Creation (4688) + command line | High volume, scales with process churn. **Command lines can contain credentials typed by admins** - treat the Security log as sensitive data downstream. Highest detection value of any single setting. |
| PowerShell module logging (4103) | Extremely high volume: one Mimikatz run = 2000+ events, ~7 MB. Logs command output too. |
| PowerShell script block logging (4104) | Moderate-high volume, ~100 events per Mimikatz run. Logs de-obfuscated code. Scripts >32 KB fragment across events. |
| PowerShell transcription (Optional) | Disk files, very storage-cheap, but land in user Documents unless an output directory is set. Attacker-deletable. |
| Filtering Platform Connection (5156/5157) | Very high volume, per-connection. The main driver of Security log growth after 4688. Size the 1 GB Security log with this in mind. |
| Sensitive Privilege Use (4673/4674) | High volume on busy servers; known-noisy with backup agents. |
| Removable Storage / Plug and Play | Volume proportional to actual USB use; low on servers. |
| File Share (5140) | Busy on file servers and DCs. Detailed File Share (5145) is deliberately excluded as noisier still. |
| RPC Events | Rare in practice; Microsoft warns it can be busy on heavy RPC servers. |
| SAM subcategory | Can be busy on DCs - watch during the pilot. |
| 1 GB Security + 1 GB PowerShell logs | Up to ~3 GB additional disk per host; confirm system volume headroom. |

Pilot guidance (from the Yamato README): run the full set on a test box
mirroring production for at least a week, then use event ID metrics (for
example Hayabusa's `eid-metrics`) to decide what to keep. SIEM-side filtering
and routing decisions are a separate design activity downstream of this host
baseline.

## WELA quick reference (v2.1.0, verified against source)

```text
.\WELA.ps1 audit-settings -Baseline <YamatoSecurity|ASD|Microsoft_Client|Microsoft_Server> [-OutType std|gui|table]
.\WELA.ps1 audit-filesize -Baseline YamatoSecurity
.\WELA.ps1 configure      -Baseline YamatoSecurity [-Auto]     # not used by this kit
.\WELA.ps1 update-rules
```

Outputs (written to the working directory, archived by `Invoke-WELACheck.ps1`):
`WELA-Audit-Result.csv`, `WELA-FileSize-Result.csv`, `UsableRules.csv`,
`UnusableRules.csv`. All output is CSV-parseable; there is no JSON output mode.

**Expected deviations in WELA output** (WELA disagreeing with the kit is not
always kit drift):

- *Process Termination, Group Membership, Kernel Object, Registry*: WELA's
  recommendation table asks for these, but Yamato's own
  EnableWindowsLogSettings batch leaves all four disabled (noise, and the
  Kernel Object / Registry subcategories log almost nothing without SACLs).
  The kit follows the batch, so these rows show as deviations permanently.
- *Computer Account Management* on non-DCs: WELA's table is role-blind; those
  events only generate on domain controllers, where the kit applies them.
- Rows where WELA recommends less than the kit (e.g. Account Lockout
  `Failure`, Process Creation `Success`): the kit's Success and Failure
  supersets them, and `Invoke-WELACheck.ps1` compares superset-aware, so
  these rows are not reported as deviations once the kit is applied.

## Assumptions and limitations

- English-language OS assumed for verification: `auditpol /r`
  "Inclusion Setting" text is localised, so the comparison logic expects
  English values. (Setting is locale-safe - GUIDs are used throughout.
  Locale-independent verification is a roadmap item.)
- Local audit policy on domain-joined hosts can be overridden by GPO at
  refresh (see quick-start notes). The legacy-vs-advanced audit policy
  override (`SCENoApplyLegacyAuditPolicy`) is Windows default-on for
  2019/2022 when advanced policy is used; the kit does not change it. If a
  legacy category-level GPO exists in your estate, resolve that at GPO level.
- File System and Registry auditing require SACLs on specific objects;
  scoping those is a per-environment design decision, out of scope for this
  host baseline.

## Contributing and SDLC

Issues and PRs welcome - especially field reports on event volumes per
setting, and the roadmap items in [ROADMAP.md](ROADMAP.md).

How changes land:

- **Branch + PR only.** Work on a feature branch, open a pull request; nothing
  goes straight to `main`.
- **CI must pass**: PSScriptAnalyzer lint (config in
  `PSScriptAnalyzerSettings.psd1`), the kit self-checks on both Windows
  PowerShell 5.1 and PowerShell 7 (`tests/Invoke-KitChecks.ps1` - run it
  locally first), and a DevSkim security scan (findings surface in the
  Security tab).
- **Dependabot** watches the GitHub Actions used by CI and opens update PRs
  weekly. The kit itself has no package dependencies by design.
- **Releases** are tags: pushing `vX.Y.Z` triggers the release workflow, which
  re-runs the checks on the tagged commit, then publishes a GitHub Release
  with `WinLogKit-vX.Y.Z.zip` and a `SHA256SUMS.txt` to verify the download.
  Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

Rules of the house: every setting lives in `LoggingBaseline.Settings.ps1` with
a plain-language purpose, every deviation from upstream gets a documented
reason, and nothing that requires third party agents.

## License

[MIT](LICENSE). The upstream Yamato Security projects are also MIT licensed.
