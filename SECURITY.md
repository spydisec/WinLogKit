# Security Policy

WinLogKit changes Windows audit and logging configuration on hosts people
care about, so security reports are taken seriously and handled quickly.

## Supported versions

Only the [latest release](https://github.com/spydisec/WinLogKit/releases)
is supported. There are no runtime dependencies to patch; the kit is plain
PowerShell, so updating means downloading the newest release zip (verify it
against the published `SHA256SUMS.txt`).

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting instead:

1. Go to the repository's **Security** tab →
   [**Report a vulnerability**](https://github.com/spydisec/WinLogKit/security/advisories/new).
2. Describe the issue, affected script(s), and reproduction steps. A
   proof-of-concept helps but is not required.

You can expect an acknowledgement within a few days. If the report is
confirmed, a fix is developed privately, released, and credited to you in
the advisory and changelog unless you prefer otherwise.

## What counts as a vulnerability here

Examples of reports that are in scope:

- A kit script that can be made to apply a setting outside its documented
  set, or one from the never-do list (reboot, service restart, log
  shrinking, `CrashOnAuditFail`, retention changes, SACLs)
- Injection into generated artefacts (Intune packs, WEF subscription XML,
  GPO files) via crafted baseline CSV content
- The `-Download` path fetching or executing something other than the
  intended, verifiable WELA release
- Anything that makes verification report PASS when the host does not
  actually match the baseline

Findings about **Windows itself** or the **upstream Yamato Security tools**
should go to Microsoft / Yamato Security respectively; happy to help route
them if you are unsure.
