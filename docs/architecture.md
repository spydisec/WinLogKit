# Architecture

How the kit works under the hood, in one picture. The claim it makes:
**all configuration derives from a single settings table (coverage
additionally reads the shipped ATT&CK snapshot), snapshots come in once
with their dates recorded, and events flow out to your collector - the kit
never talks to the internet at runtime.**

<figure markdown>
<svg viewBox="0 0 660 620" role="img" aria-label="Vendored snapshots feed two destinations: Yamato baselines into the settings table, and the ATT&amp;CK snapshot into the coverage report. Enable applies and Test verifies the settings table on the Windows host, generators compile fleet artefacts from it, host events flow to the Windows Event Log, over WEF to a collector, and hand off to the SIEM." style="max-width: 660px; width: 100%; height: auto; font-family: inherit;">
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="currentColor"/>
    </marker>
  </defs>
  <g fill="none" stroke="currentColor" stroke-width="1.4">
    <!-- left column boxes -->
    <rect x="20"  y="10"  width="290" height="66" rx="6"/>
    <rect x="20"  y="130" width="290" height="50" rx="6" stroke-width="2.5" style="stroke: var(--md-primary-fg-color, #546e7a)"/>
    <rect x="20"  y="250" width="290" height="66" rx="6"/>
    <rect x="20"  y="370" width="290" height="44" rx="6"/>
    <rect x="20"  y="468" width="290" height="52" rx="6"/>
    <rect x="20"  y="572" width="290" height="40" rx="6" stroke-dasharray="5 4"/>
    <!-- right column boxes -->
    <rect x="360" y="120" width="280" height="50" rx="6"/>
    <rect x="360" y="250" width="280" height="66" rx="6"/>
  </g>
  <g fill="currentColor" font-size="13" text-anchor="middle">
    <text x="165" y="32"  font-weight="bold">Vendored snapshots</text>
    <text x="165" y="50"  font-size="11.5">Yamato baselines &#183; MITRE ATT&amp;CK</text>
    <text x="165" y="66"  font-size="11.5">copied once, dated, credited</text>
    <text x="165" y="151" font-weight="bold">Settings table</text>
    <text x="165" y="169" font-size="11.5">the single source of truth</text>
    <text x="165" y="272" font-weight="bold">Windows host</text>
    <text x="165" y="290" font-size="11.5">audit policy &#183; channels &#183; registry</text>
    <text x="165" y="306" font-size="11.5">SMB auditing</text>
    <text x="165" y="396" font-weight="bold">Windows Event Log</text>
    <text x="165" y="490" font-weight="bold">Event Collector</text>
    <text x="165" y="508" font-size="11.5">ForwardedEvents log</text>
    <text x="165" y="596" font-weight="bold">SIEM</text>
    <text x="500" y="141" font-weight="bold">Coverage report</text>
    <text x="500" y="159" font-size="11.5">Export-AttackCoverage</text>
    <text x="500" y="272" font-weight="bold">Fleet artefacts</text>
    <text x="500" y="290" font-size="11.5">Intune pack &#183; WEF XML</text>
    <text x="500" y="306" font-size="11.5">GPO pack</text>
  </g>
  <g stroke="currentColor" stroke-width="1.4" fill="none" marker-end="url(#arr)">
    <line x1="165" y1="76"  x2="165" y2="128"/>
    <line x1="165" y1="180" x2="165" y2="248"/>
    <line x1="165" y1="316" x2="165" y2="368"/>
    <line x1="165" y1="414" x2="165" y2="466"/>
    <line x1="165" y1="520" x2="165" y2="570"/>
    <!-- snapshots -> coverage report (ATT&CK data, elbow right) -->
    <path d="M 310 43 L 500 43 L 500 118"/>
    <!-- settings -> generators (elbow right, past the coverage box) -->
    <path d="M 310 168 L 345 168 L 345 210 L 500 210 L 500 248"/>
    <!-- fleet -> host (Intune/GPO apply) -->
    <path d="M 360 283 L 312 283"/>
    <!-- fleet -> collector (WEF subscription, elbow down right) -->
    <path d="M 500 316 L 500 494 L 312 494" stroke-dasharray="5 4"/>
  </g>
  <g fill="currentColor" font-size="11">
    <text x="175" y="100"  text-anchor="start">Yamato: extracted once, drift-checked</text>
    <text x="405" y="36"   text-anchor="middle">ATT&amp;CK snapshot</text>
    <text x="175" y="212"  text-anchor="start">Enable applies &#183; Test verifies</text>
    <text x="175" y="344"  text-anchor="start">events</text>
    <text x="175" y="442"  text-anchor="start">WEF push (WinRM)</text>
    <text x="175" y="548"  text-anchor="start">handoff &#8212; out of kit scope</text>
    <text x="422" y="203"  text-anchor="middle">generators compile</text>
    <text x="336" y="276"  text-anchor="middle" font-size="10.5">apply</text>
    <text x="405" y="486"  text-anchor="middle" font-size="10.5">WEF subscription</text>
  </g>
</svg>
<figcaption>One settings table feeds the host, the fleet artefacts and the verification; events leave through the Windows Event Log to your collector.</figcaption>
</figure>

Reading it top to bottom:

- **Snapshots in**: the Yamato baselines were extracted once into the
  settings table, and the MITRE ATT&CK data into the coverage mapping
  (`data/attack/`) - two separate destinations, each with source, version
  and date recorded (`data/*/README.md`); CI drift-checks everything
  generated from them.
- **One table**: every script - the builder, Enable, Test, the coverage
  report and all three fleet generators - dot-sources
  `LoggingBaseline.Settings.ps1`, so applied config, deployed artefacts and
  verification can never disagree.
- **Events out**: hosts write to the Windows Event Log service;
  [Windows Event Forwarding](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
  carries selected channels over WinRM to a collector's ForwardedEvents
  log; your SIEM picks up there, deliberately outside the kit.

Which application each piece touches: Enable/Test drive `auditpol.exe`,
`wevtutil.exe`, the registry and the SMB configuration cmdlets; the Intune
pack is consumed by **Microsoft Intune** (Scripts and remediations); the
subscription XML by the **Windows Event Collector** (`wecutil`); the GPO
pack by **GPMC / LGPO.exe**; and WELA runs as an independent checker
alongside Test.

## Behaviour category mapping

The kit organises settings by **behaviour category** rather than by channel,
so a monitoring requirement ("we must see scheduled task abuse") traces to
the exact settings that satisfy it. "Subcategory" = advanced audit policy
subcategory (Security log). DC = generated on domain controllers only.
HV = HighVolume tier.

| Category | Audit subcategories | Channels | Registry | Coverage |
|---|---|---|---|---|
| Authentication | Credential Validation; Logon; Logoff; Account Lockout; Other Logon/Logoff; Special Logon; Kerberos Authentication Service (DC); Kerberos Service Ticket Operations (DC) | Security; Microsoft-Windows-NTLM/Operational | MSV1_0 `RestrictSendingNTLMTraffic=1` (audit), `AuditReceivingNTLMTraffic=2`; Netlogon `AuditNTLMInDomain=7` (DC) | Full |
| Execution | Process Creation (HV) | Security; WMI-Activity/Operational; Bits-Client/Operational; AppLocker x4; Diagnosis-Scripted/Operational | `ProcessCreationIncludeCmdLine_Enabled=1` (HV) | Full via 4688+cmdline; no file hashes or DLL loads natively (accepted gap) |
| Account and access change | User Account Management; Security Group Management; Other Account Management; Computer Account Management (DC); Distribution Group Management (DC); Authentication Policy Change | Security | - | Full |
| Privilege use | Special Logon (4672); Sensitive Privilege Use (HV) | Security | - | Full |
| Logging tampered with | Audit Policy Change (4719); Security State Change; System Integrity; Other System Events (failure) | Security (1100/1102/1104 default); System (104); Defender/Operational (tamper) | - | Full |
| Software and service install | Security System Extension (4697) | System (7045); Application (MsiInstaller); CodeIntegrity/Operational; PrintService Admin + Operational | - | Full |
| Remote access | Logon (types 3/10); Other Logon/Logoff (4778/4779); RPC Events | TerminalServices-LocalSessionManager/Operational; SmbClient/Security | - | Full |
| Scheduled and automated tasks | Other Object Access (4698-4702) | TaskScheduler/Operational; WMI-Activity/Operational | - | Full |
| Scripting and command line | Process Creation (HV) | PowerShell/Operational (4103/4104); Windows PowerShell; PowerShellCore/Operational; Diagnosis-Scripted | Script block + module logging (HV); cmdline (HV); transcription (Optional) | Full for PowerShell; other interpreters visible only via 4688 command lines |
| Persistence | Security System Extension; Other Object Access; Directory Service Changes (DC) | System (7045); TaskScheduler; WMI-Activity; Bits-Client | - | **Partial**: registry autoruns (Run keys, IFEO) need the Registry subcategory + per-key SACLs, not in this baseline |
| Removable and external devices | Plug and Play (6416); Removable Storage (4663) | DriverFrameworks-UserMode/Operational | - | Full |
| Blocked and denied activity | Account Lockout; Filtering Platform Connection blocks (HV) | Defender/Operational; AppLocker x4; CodeIntegrity; Security-Mitigations x2; Firewall | - | Full (AppLocker channels populate only if AppLocker policy deployed) |
| Directory and identity store | Directory Service Access (DC); Directory Service Changes (DC); SAM; Kerberos Authentication Service (DC) | Security | - | Full on DCs; standalone = local SAM only (by design) |
| File and object access | File Share (5140/5142-5144); Removable Storage | Security | - | **Partial**: per-file auditing (4663) needs File System subcategory + SACLs on chosen paths, a per-asset design decision, deliberately not blanket-enabled |
| Certificates and keys | Certification Services (4898/4899); Other Policy Change (CNG) | Security; Crypto-DPAPI/Debug (Optional) | AD CS `AuditFilter=127` (only when AD CS installed; CertSvc restart) | Full where AD CS present; limited elsewhere (accepted) |
| Network flow and sessions | Filtering Platform Connection 5156/5157 (HV); RPC Events | Firewall channel; SmbClient/Security | - | **Partial**: no byte counts / flow aggregation natively; true flow telemetry needs network-layer sources, outside host scope |

The partial rows are the recognised gaps of agentless native logging
(registry autoruns, per-file SACLs, flow statistics, execution depth beyond
4688 command lines) - do not expect a native setting to close them; see
[Safety - known limits](safety.md#known-limits-stated-plainly).
