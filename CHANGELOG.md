# Changelog

All notable changes to WinLogKit. Versions follow [SemVer](https://semver.org/);
releases are tagged `vX.Y.Z` and published with a zip + SHA256 checksum.

## v0.2.0 - 2026-08-31

### Added
- Windows Server 2025 support: new SMB signing/encryption capability auditing
  (`AuditClientDoesNotSupport*` / `AuditServerDoesNotSupport*` via the SMB
  configuration cmdlets, events 3021/3022 and 31998/31999) plus sizing for the
  `SMBServer/Audit` and `SmbClient/Audit` channels. OS-gated: reported
  NOT APPLICABLE on 2019/2022.
- `New-LoggingBaseline.ps1`: interactive baseline builder with the kit
  recommendation and per-item volume/stability risk notes; writes an
  Excel-editable selection CSV.
- `-BaselineFile` on Enable/Test: apply and verify exactly the selected set.
- Stability safety documentation (never-do list: CrashOnAuditFail,
  do-not-overwrite retention, global object access auditing, blanket SACLs),
  grounded in Microsoft documentation, with `Risk` metadata on heavy settings.
- SDLC: CI (PSScriptAnalyzer lint, kit self-checks on Windows PowerShell 5.1
  and PowerShell 7, DevSkim security scan), release workflow (zip + SHA256 on
  version tags), Dependabot for GitHub Actions, self-check harness in `tests/`.

### Notes
- On Windows Server 2025, NTLMv1 is removed by the OS and the SMB client
  supports NTLM blocking. The kit's NTLM settings remain audit-only and safe.

## v0.1.0 - 2026-08-31

- Initial release: Yamato Security logging baselines as an enable/test/verify
  kit for Windows Server 2019/2022. Tiered enablement (Core / HighVolume /
  Optional), idempotent with `-WhatIf` and `-Rollback`, read-only verification
  with per-category PASS/FAIL/NA and CSV output, WELA-based independent
  checking with archived evidence.
