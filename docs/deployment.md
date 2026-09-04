# Deploy

How to roll a baseline out to many machines through Intune or Group Policy.
Both generators compile from the settings table, or from the same
`-BaselineFile` selection CSV used everywhere else, so deployed artefacts
are generated to match the tested baseline. Regenerate after any settings
change; the generated files say not to edit them by hand.

Central collection (WEF / WEC) has its own page: [Collect](wec.md).

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
Create**: run using logged-on credentials **No** (SYSTEM), enforce script
signature check **No** (the generated scripts are unsigned; with Yes the
device's execution policy applies and they must be signed by a trusted
publisher, per
[Microsoft's remediation prerequisites](https://learn.microsoft.com/intune/device-management/tools/deploy-remediations#prerequisites)),
64-bit PowerShell **Yes**. Endpoints need nothing but the two uploaded files -
role- and version-gating happens at runtime on each host. The AD CS
AuditFilter is excluded from packs by design (it needs a CertSvc restart,
which does not belong in unattended remediation).

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
