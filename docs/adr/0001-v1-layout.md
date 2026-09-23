# ADR-001: v1.0 layout and docs cut

**Status:** Accepted (implemented in v1.0.0, 2026-09-04)
**Deciders:** Maintainer (@spydisec)
**Record:** written up after the fact; the full decision and discussion are in
[PR #30](https://github.com/spydisec/WinLogKit/pull/30) and the steps that
followed (#31, #32).

## Context

Before v1.0 the kit had grown to 13 docs pages, a long README, a landing
page with its own styling, a `ROADMAP.md`, and helper functions copied
between scripts. A new reader couldn't quickly see which three scripts
mattered.

## Decision

Three steps, one release:

1. **Docs cut.** The README goes down to one screen and is reused as the
   site home page. Pages go from 13 to 10 (Collect absorbs the WEF parts of
   Deployment, Architecture merges into Coverage, the FAQ into Safety), and
   `ROADMAP.md` is replaced by GitHub issues.
2. **One copy of the shared helpers.** `WinLogKit.Common.ps1` holds what
   Enable, Test, the reports and the fleet generators used to copy; the
   self-checks fail if a function is defined twice.
3. **Layout.** The three host scripts stay at the root with the settings
   table (renamed `WinLogKit.Settings.ps1`) and helpers; fleet generators
   move to `fleet\`, reports to `report\`.

## Consequences

- Paths changed, hence v1.0.0; no setting changed.
- The roadmap list from PR #30 was meant to become issues after merge but
  never did; converting the items that still apply is an ADR-002 action.
- Superseded in part by [ADR-002](0002-scope-and-simplification.md), which
  narrows the scope and removes `report\`.
