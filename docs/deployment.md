# Deploy

How to roll a baseline out to many machines: the Intune **Settings
catalog** for cloud-managed devices, **Group Policy** for domain-joined
fleets. Both are described from the settings table itself, and the GPO
pack is generated from the same `-BaselineFile` selection CSV used
everywhere else, so what you deploy matches the tested baseline.
Regenerate after any settings change; generated files say not to edit
them by hand.

Central collection (WEF / WEC) has its own page: [Collect](wec.md).

## Intune (workstations and cloud-managed servers)

Build a **Settings catalog** profile from the
[Settings catalog](intune-csp.md) page: it maps each kit setting to its
Policy CSP, with the value to set and Microsoft's page. No scripts run on
the endpoints.

!!! note
    The Settings catalog mapping is built from Microsoft's CSP
    documentation and checked in CI, but hasn't yet been field-tested in a
    real tenant ([#46](https://github.com/spydisec/WinLogKit/issues/46)).
    Pilot it on a small device group first.

What the catalog covers: audit policy, command-line capture, Windows
PowerShell logging, incoming NTLM auditing, SMB auditing (Windows 11 24H2
and later) and the Application, Security and System log sizes. What it
can't: the sizes and enablement of the other kit logs, the 32-bit and
PowerShell 7 copies of the PowerShell policies, and outgoing NTLM
auditing. The page lists each one and why. On a device managed only
through the catalog, `Test-LoggingBaseline.ps1` reports those rows as
FAIL; that's expected, and running `Enable-LoggingBaseline.ps1` once on
the device covers them.
## GPO (domain-joined fleets)

```powershell
.\fleet\New-GpoPack.ps1 [-BaselineFile <csv>] [-IncludeHighVolume]
```

Produces:

- `audit.csv` - the advanced audit policy in Windows' own audit CSV format
  (GUID-driven; the same shape `auditpol /backup` emits)
- `registry.txt` - LGPO text format for the policy-key registry values
  (PowerShell logging, command line capture, SMB signing and encryption
  auditing)

**Building a domain GPO by hand?** [Group Policy paths](gpo-paths.md)
lists where every setting lives in the Group Policy Management Editor and
what to set it to, generated from the same settings table.

**Local, image builds or air-gapped estates:** apply the files with
LGPO.exe from Microsoft's
[Security Compliance Toolkit](https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10)
(`LGPO.exe /ac audit.csv`, `LGPO.exe /t registry.txt`). LGPO can also
export a machine's local policy as a GPO backup, so a reference machine
configured this way can seed a domain GPO through GPMC's Import Settings
(see LGPO's documentation in the toolkit).

**What the GPO pack can't deliver** (the generator prints these as
reminders, and the [Group Policy paths](gpo-paths.md) page lists them):

- Log sizes and enablement, except the Application, Security and System
  sizes, which have an Event Log Service template. Size the rest with a
  computer startup script, or run `Enable-LoggingBaseline.ps1` on the host.
- NTLM audit values: GPO Security Options, set in the editor (paths on
  the page).
- The AD CS AuditFilter: it needs a CertSvc restart, so set it on the CA
  in a change window.

!!! warning "Partial selections and apply semantics"
    A pack generated from a narrow `-BaselineFile` covers only the selected
    subcategories; how unlisted subcategories fare depends on the applying
    tool and existing policy. Likewise `LGPO /t` is additive - a smaller
    pack does not remove previously applied registry values. The generator
    prints both warnings when they apply. The invariant that protects you
    either way: **always verify the effective state afterwards** with
    `Test-LoggingBaseline.ps1`, which reads the live audit policy
    ([`auditpol /backup`](https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-backup),
    read by its numeric setting values rather than the display text, so it
    works on any Windows language) and registry, not the files you applied.

!!! note
    On domain-joined hosts, local audit policy holds only until Group Policy
    reapplies at refresh (see
    [Group Policy processing](https://learn.microsoft.com/windows-server/identity/ad-ds/manage/group-policy/group-policy-processing)).
    For fleets, treat the kit's local apply as the specification and pilot;
    deliver via the artefacts above. `Test-LoggingBaseline.ps1` verifies the
    *effective* state either way.
