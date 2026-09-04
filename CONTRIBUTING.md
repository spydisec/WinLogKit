# Contributing to WinLogKit

Thanks for considering a contribution. The most valuable thing you can send,
even without writing a line of code, is a **field report**: real event
volumes per setting from a real environment (host role, rough events/day or
MB/day per channel, which settings you ended up dropping and why). That data
is what tunes the presets. Open an issue with the *Field report* template.

## Ways to contribute

- **Field reports** - volumes, pilot experiences, settings that misbehaved
  on a particular Windows version or role.
- **Bug reports** - something applied, verified or generated incorrectly.
  Use the *Bug report* template and include the transcript from `.\Logs\`
  or the Results CSVs where relevant.
- **Docs** - unclear wording, missing steps, broken links.
- **Code** - fixes and planned work (open issues labelled `enhancement`). For
  anything non-trivial, open an issue first so the approach is agreed
  before you spend time on it.

## Ground rules for changes

- **Every setting lives in `LoggingBaseline.Settings.ps1`** with a
  plain-language purpose and, where it matters, a risk note. Scripts,
  presets, packs and docs derive from it; never hard-code a setting
  anywhere else.
- **Shared helpers live in `WinLogKit.Common.ps1`** (host probes, registry
  reads, the audit policy reader, the selection model). A function
  defined in two kit files fails the self-checks. The Intune pack
  generator embeds its own helpers on purpose: the generated scripts must
  run alone.
- **Windows PowerShell 5.1 compatible, no external modules, no agents.**
  The design intent is a kit that runs on a bare server with nothing
  installed. PowerShell 7 is fully supported (CI tests every change on
  both engines), but 5.1 stays the compatibility floor: it is what ships
  with Windows and what Intune remediations execute under, so nothing
  5.1-incompatible can be merged.
- **The never-do list is non-negotiable**: nothing that reboots, restarts
  services, shrinks logs, enables `CrashOnAuditFail`, sets "do not
  overwrite" retention, or applies blanket SACLs
  ([Safety](https://spydisec.github.io/WinLogKit/safety/)).
- **Deviations from the Yamato sources need a documented reason** in the
  deviations table.
- **Generated files are never edited by hand**: presets, the docs Reference
  page, Intune packs and GPO artefacts are regenerated from their `tools\`
  generators, and CI fails on drift.

## How changes land

1. Fork (or branch) and make your change on a feature branch; nothing goes
   straight to `main`.
2. Run the self-checks locally before pushing:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-KitChecks.ps1
   ```

3. Open a pull request. CI must pass:
   - **PSScriptAnalyzer** lint (config in `PSScriptAnalyzerSettings.psd1`)
   - the **kit self-checks** on both Windows PowerShell 5.1 and PowerShell 7
   - a **DevSkim** security scan
4. Automated review comments (CodeRabbit) are triaged, not blindly applied;
   maintainer review follows.

**Releases** are tags: pushing `vX.Y.Z` triggers the release workflow, which
re-runs the checks on the tagged commit and publishes a zip +
`SHA256SUMS.txt`. Changes are tracked in [CHANGELOG.md](CHANGELOG.md).

## Security issues

Please do not open a public issue for a vulnerability - see
[SECURITY.md](SECURITY.md).

## License

By contributing you agree your contribution is licensed under the
[MIT License](LICENSE), the same as the project and the upstream Yamato
Security sources.
