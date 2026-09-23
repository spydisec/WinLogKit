# ADR-003: Intune through the Settings catalog only

**Status:** Accepted (2026-09-24)
**Date:** 2026-09-24
**Deciders:** Maintainer (@spydisec)
**Amends:** [ADR-002](0002-scope-and-simplification.md), which kept the generated Intune remediation pack as the route for cloud-managed endpoints.
**Issue:** [#63](https://github.com/spydisec/WinLogKit/issues/63)

## Context

Since #47 and #48 the kit documents two Intune routes: the generated remediation pack (`fleet\New-IntuneRemediationPack.ps1`, a detection and remediation script pair run as SYSTEM) and the Settings catalog page, which maps every setting to its Policy CSP. Having both means two things to explain, and the pack is the heavier one: a generator with its own embedded copy of the helpers, unsigned scripts to upload, a schedule, and a behaviour nobody has field-tested in a real tenant (#46).

Most organisations already deliver audit policy through the Settings catalog. ADR-002's goal ("turn on the native logging, prove it is recording, undo it") doesn't need scripts running on endpoints to reach Intune-managed devices.

## Decision

Intune is delivered through the **Settings catalog only**. The remediation pack generator, its tests and its documentation are removed. The Settings catalog page is the one Intune route; the Deploy page points to it.

## Options considered

| Option | For | Against |
|---|---|---|
| **A. Keep both routes** | Full coverage on Intune-only devices | Two routes to explain and maintain; the heavier one is untested |
| **B. Settings catalog only** (chosen) | One route, no scripts on endpoints, how most tenants already work | Some settings have no CSP (below) |
| C. Remediation pack only | Full coverage | Ignores how most tenants deliver policy; scripts to sign and schedule |

## Consequences

- **Intune-only devices don't get the settings that have no CSP:** the size and enablement of 25 of the 28 kit logs (logs that are off by default, such as TaskScheduler/Operational, stay off), the 32-bit and PowerShell 7 copies of the PowerShell logging policies, and outgoing NTLM auditing (its CSP documents value 1 as "Deny all domain accounts"). The Settings catalog page lists each one and why.
- `Test-LoggingBaseline.ps1` reports those rows as FAIL on a catalog-only device. That's documented as expected; running `Enable-LoggingBaseline.ps1` once on the device covers them.
- Existing users of the pack: remediations already in a tenant keep running as they are, but aren't maintained. The CHANGELOG says what to use instead.
- Easier: one Intune story, one fewer generator, no helper copies to keep in sync.
- To revisit: an importable Settings catalog profile (JSON) once the setting definition IDs are verified in a tenant; an opt-in route for the no-CSP settings if field reports show they're needed on Intune-only fleets.
