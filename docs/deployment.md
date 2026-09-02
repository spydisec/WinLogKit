# Fleet Deployment

How to roll a baseline out to many machines - through Intune, Windows
Event Forwarding, or Group Policy - all generated from the same tested
selection (tier switches, or optionally a baseline CSV). One mental model
for everything on this page:

```text
generate (this kit, on each host)  ->  transport (WEF/WEC)  ->  ingest (your SIEM)
```

The kit owns *generate* and helps you set up *transport*. *Ingest* -
agents, connectors, SIEM-side filtering - is deliberately out of scope: the
handoff point is the ForwardedEvents log on your collector.

All three generators below compile from the settings table (or the same
`-BaselineFile` selection CSV used everywhere else), so deployed artefacts
cannot drift from the tested baseline. Regenerate after any settings
change; the generated files say not to edit them by hand.

## Intune (workstations and cloud-managed servers)

```powershell
.\New-IntuneRemediationPack.ps1 [-BaselineFile <csv>] [-IncludeHighVolume] [-IncludeOptional]
```

Produces a self-contained pair for Intune remediations:

- `Detect-LoggingBaseline.ps1` - exit 0 compliant / exit 1 with a one-line
  drift summary
- `Remediate-LoggingBaseline.ps1` - applies only what is below baseline;
  never shrinks logs, never restarts anything

Upload under **Devices > Manage devices > Scripts and remediations >
Create**: run using logged-on credentials **No** (SYSTEM), 64-bit
PowerShell **Yes**. Endpoints need nothing but the two uploaded files -
role- and version-gating happens at runtime on each host. The AD CS
AuditFilter is excluded from packs by design (it needs a CertSvc restart,
which does not belong in unattended remediation).

## WEF/WEC (central collection, agentless)

```powershell
.\New-WefSubscription.ps1 [-BaselineFile <csv>] [-SubscriptionId <name>]
```

Generates a source-initiated subscription XML - one query per selected
channel. Transport defaults (`Events` format, 30s/500-item batching, 1h
heartbeat, source SDDL) live in the settings table and are overridable per
run. The script prints the full setup:

```text
Collector:  winrm qc -q            (WinRM listener first)
            wecutil qc /q          (then the collector service)
            wecutil cs .\WEF\WinLogKit-Baseline.xml
            wevtutil sl ForwardedEvents /ms:1073741824
Sources:    winrm qc -q   (WinRM must be configured on each source too - or
                           enable the WinRM service via GPO fleet-wide)
            GPO > Event Forwarding > Configure target Subscription Manager
            Server=http://<collector-fqdn>:5985/wsman/SubscriptionManager/WEC,Refresh=60
```

Per [Microsoft's source-initiated subscription procedure](https://learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription),
both ends need WinRM: the collector to listen, the sources to forward.

The classic trap: for the Security log, add NETWORK SERVICE to **Event Log
Readers** on sources, or Security forwarding silently fails. Verify either
side with:

```powershell
.\Test-LoggingBaseline.ps1 -WefRole Source      # on a forwarding host
.\Test-LoggingBaseline.ps1 -WefRole Collector   # on the WEC
```

Whole-channel forwarding is the deliberate starting point - your baseline
selection is the coarse filter. Graduate to curated per-event XPath queries
using [Microsoft's WEF intrusion-detection guidance](https://learn.microsoft.com/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
once you have observed real volume.

Beyond generating the subscription: the [WEC Collector](wec.md) page covers
reading and verifying an existing collector (subscription anatomy, runtime
status, the silent failures), and [Sentinel KQL](kql.md) covers the onward
hop to a SIEM workspace and the queries that prove the chain end to end.

## GPO (domain-joined fleets)

```powershell
.\New-GpoPack.ps1 [-BaselineFile <csv>] [-IncludeHighVolume] [-IncludeOptional]
```

Produces:

- `audit.csv` - the advanced audit policy in Windows' own audit CSV format
  (GUID-driven; the same shape `auditpol /backup` emits)
- `registry.txt` - LGPO text format for the policy-key registry values
  (PowerShell logging, command line capture)

Apply locally or in image builds with LGPO.exe from Microsoft's Security
Compliance Toolkit (`LGPO.exe /ac audit.csv`, `LGPO.exe /t registry.txt`);
for domain GPOs, mirror `audit.csv` in Advanced Audit Policy Configuration.
Printed reminders cover what GPO packs deliberately exclude: channel
sizing (startup script or Intune pack), NTLM audit values (GPO Security
Options), SMB auditing (`Set-Smb*Configuration`), AD CS AuditFilter.

!!! warning "Partial selections and apply semantics"
    A pack generated from a narrow `-BaselineFile` covers only the selected
    subcategories; how unlisted subcategories fare depends on the applying
    tool and existing policy. Likewise `LGPO /t` is additive - a smaller
    pack does not remove previously applied registry values. The generator
    prints both warnings when they apply. The invariant that protects you
    either way: **always verify the effective state afterwards** with
    `Test-LoggingBaseline.ps1`, which reads the live audit policy
    (`auditpol /get /category:* /r`) and registry, not the files you applied.

!!! note
    On domain-joined hosts, local audit policy holds only until Group Policy
    reapplies at refresh (see
    [Group Policy processing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)).
    For fleets, treat the kit's local apply as the specification and pilot;
    deliver via the artefacts above. `Test-LoggingBaseline.ps1` verifies the
    *effective* state either way.
