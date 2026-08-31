# FAQ

## Does the kit send anything anywhere, or fetch live data?

No. The kit is a static snapshot: the Yamato baselines and the OSSEM-DM
ATT&CK mappings are vendored with recorded provenance (source, commit,
date). Nothing is fetched at runtime, and nothing about your hosts,
results or baselines leaves them. The single optional network action is
`Invoke-WELACheck.ps1 -Download`, which fetches WELA from GitHub to your
machine when you explicitly ask.

## How is this different from just running Yamato's batch script?

Same settings, operationalised: idempotent apply with `-WhatIf` and
rollback, tiered volume decisions, read-only verification with evidence
CSVs, per-role baseline files, fleet delivery (Intune/WEF/GPO) compiled
from one settings table, and ATT&CK coverage numbers for the selection.
Plus a handful of documented fixes to upstream quirks (e.g. the batch
sizes PrintService/Operational but never enables it; WELA's `configure`
sets an NTLM value that *blocks* rather than audits).

## Why isn't Sysmon included?

Kit scope is native Windows configuration only - environments where agents
are unwelcome (change-restricted servers, OT-adjacent estates). Sysmon is
excellent; if you can run it, run it (the coverage report even tells you
which techniques are Sysmon-only). The kit covers the ground available
without it.

## Something broke / I want out. How do I undo everything?

```powershell
.\Enable-LoggingBaseline.ps1 -Rollback
```

restores the audit policy, channel sizes/state and registry values captured
on the first real run. Nothing in the kit requires a reboot.

Backups are automatic, and always taken **before** any change: the first
real apply captures the complete pre-kit state to `.\Baseline\` (that is
what `-Rollback` restores), and every later apply saves a timestamped
pre-change snapshot to `.\Baseline\snapshots\<timestamp>\` - so stepping
from, say, Minimal to Heavy leaves a point-in-time record. To return to an
intermediate state rather than the very beginning:
`auditpol /restore /file:<snapshot>\auditpol-backup.csv`, plus the channel
and registry values recorded in that snapshot's `State.json`.

## Can I run this on a domain controller?

Yes - DC-only items (Kerberos, Directory Service subcategories, and more)
activate automatically on DCs and report NOT APPLICABLE elsewhere. Mind the
volume notes for DCs (SAM, File Share, Kerberos are busy there) and pilot
on one DC first.

## Windows Home edition?

Works - the kit's mechanisms (`auditpol`, `wevtutil`, registry) do not
depend on Group Policy tooling, which Home lacks. The kit's own workstation
field testing was done on Windows 11 Home: full apply, verify (all 16
categories PASS) and rollback.

## Does a "PASS" mean I'm detecting attacks?

No - it means the configured events are being generated and retained.
Detection needs rules on top (Sigma, SIEM analytics). WELA's rule counts
and the [coverage mapping](mapping.md) tell you what your events *support*.

## How do I update the kit without losing my baselines?

Your selection CSVs and per-host output folders are separate from the kit
scripts. Pull the new release, keep your CSVs, rerun
`Test-LoggingBaseline.ps1 -BaselineFile <yours>` - the settings table may
have new items, which show as unlisted/excluded until you re-run the
builder and re-select.
