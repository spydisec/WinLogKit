# Add-ons

Optional extras that sit outside the native baseline. Each one is
self-contained in `addons\<name>\`, is never touched by the enable / test /
deploy scripts, and states plainly what it depends on and why it exists.

## AutorunsToWinEventLog

**What it does:** a daily scheduled task runs Sysinternals `autorunsc` and
writes every autostart entry it finds (Run keys, services, drivers,
scheduled tasks, Winlogon, IFEO, codecs, WMI, Office add-ins - every
[Autoruns category](https://learn.microsoft.com/sysinternals/downloads/autoruns))
into a dedicated **Autoruns** event log, one event per entry. From there it
rides the same WEF subscription or AMA rule as everything else, so
persistence hunting happens in the SIEM: diff today's inventory against
yesterday's, alert on an unsigned binary in a Run key, pivot on a hash.

**Why it is an add-on and not a baseline setting:** the kit's core is
native configuration only. Registry autostart locations are the one
[Persistence gap](architecture.md#behaviour-category-mapping) native
auditing cannot cover without per-key SACLs (the
[Audit Registry](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-registry)
subcategory only records access to keys that carry one), and Autoruns is
the long-standing answer to it - but it is a Sysinternals binary, so it
lives here, opt-in, clearly labelled. Be precise about what it gives you:
a **daily inventory** (what is persisted right now, diffable day to day),
not real-time change auditing. A change made and reverted between two
runs is invisible to it; only a registry SACL sees that.

### Install, verify, remove

From an elevated prompt in the kit folder. Nothing is fetched unless you
say so, matching the kit's WELA convention:

```powershell
# See every step first
.\addons\AutorunsToWinEventLog\Install-AutorunsToWinEventLog.ps1 -Download -WhatIf

# Install (downloads autorunsc over HTTPS, verifies its Microsoft signature) and run once now
.\addons\AutorunsToWinEventLog\Install-AutorunsToWinEventLog.ps1 -Download -RunNow

# Air-gapped: bring the binary from the Sysinternals Suite instead
.\addons\AutorunsToWinEventLog\Install-AutorunsToWinEventLog.ps1 -AutorunscPath D:\SysinternalsSuite\autorunsc64.exe

# Verify: task state, last result, log size, last run summary, any failure
.\addons\AutorunsToWinEventLog\Install-AutorunsToWinEventLog.ps1 -Status

# Remove the task, source and files (the log and its records are kept unless -RemoveLog)
.\addons\AutorunsToWinEventLog\Install-AutorunsToWinEventLog.ps1 -Uninstall
```

What install does: creates `%ProgramFiles%\WinLogKit\AutorunsToWinEventLog`,
places `autorunsc64.exe` (or `autorunsc.exe` on 32-bit) and the payload
script there, creates the `Autoruns` event log sized to 128 MB (about a
month of daily runs) with overwrite-as-needed retention, and registers
the task `AutorunsToWinEventLog` (daily at 01:00 as SYSTEM, 60-minute
limit, runs when next available if the time was missed). `-DailyAt` and
`-LogMaxMB` adjust the defaults. Everything is idempotent. A custom
`-InstallDir` must sit under Program Files or the Windows folder and grant
write rights only to administrators and SYSTEM - the installer refuses
anything else, because a task running as SYSTEM from a folder a standard
user can alter is a privilege escalation waiting to happen.

A quick look at the result on the host:

```powershell
Get-WinEvent -LogName Autoruns -MaxEvents 3 | Format-List TimeCreated, Id, Message
Get-WinEvent -FilterHashtable @{ LogName = 'Autoruns'; Id = 100 } -MaxEvents 1   # last run summary
```

### Events

| ID | Meaning | Message |
|---|---|---|
| 1 | One autostart entry | Every autorunsc CSV column as `Key : Value` lines - Time, Entry Location, Entry, Enabled, Category, Profile, Description, Signer, Company, Image Path, Version, Launch String, MD5, SHA-1, PESHA-1, PESHA-256, SHA-256, IMP |
| 100 | Run summary | Entries written, duration, autorunsc version, host - alert when a host stops producing this daily |
| 101 | Run failure | The error text - alert on any occurrence |

Volume, observed on one Windows 11 24H2 workstation with autorunsc 14.3
(2026-09-03, run as SYSTEM with all profiles): 1,640 entries in 61
seconds, **4.1 MB of event log per run** (event records carry overhead
well beyond the ~1 MB CSV). Servers and hosts with many installed products
will differ; measure your own with `-Status`. Multiply by fleet size
before pointing it at a billable table; the roadmap has a diff mode for
exactly that reason.

### Collecting it centrally

- **WEF**: add the channel to the
  [subscription](https://learn.microsoft.com/windows/win32/wec/setting-up-a-source-initiated-subscription)
  query - `<Select Path="Autoruns">*</Select>`. This is a manual addition:
  the kit's subscription generator only knows the channels in the settings
  table, and the add-on deliberately is not one of them. Sources need
  nothing extra: it is a classic log readable by the forwarding service.
- **AMA**: add `Autoruns!*` to the
  [DCR's Windows event log XPath list](https://learn.microsoft.com/azure/azure-monitor/agents/data-collection-windows-events)
  (or `ForwardedEvents!*` already covers it when forwarded via WEF).
- **Sentinel**: the events land in `WindowsEvent` with `Channel ==
  "Autoruns"`. Inspect a few rows to see where AMA placed the message text
  for classic-log events in your workspace, then parse the `Key : Value`
  lines from there:

```kusto
WindowsEvent
| where TimeGenerated > ago(24h) and Channel == "Autoruns"
| summarize Entries = countif(EventID == 1), Summaries = countif(EventID == 100), Failures = countif(EventID == 101) by Computer
| order by Entries desc
```

### Design choices

Each of these is a decision with a reason, so you can disagree with eyes
open:

- **Hashes and signature verification, no VirusTotal.** `autorunsc` runs
  with `-h -s` so every entry carries its hashes and signer, and nothing
  leaves the host. VirusTotal or any other enrichment happens SIEM-side,
  where it belongs, and no host needs internet access to run.
- **Microsoft-signed entries are kept.** A design decision, not a
  platform rule: `autorunsc` can hide them (`-m`) and many deployments do
  for volume, but that hides persistence that rides a signed Microsoft
  binary (illustrated by
  [Huntress's evading-Autoruns research](https://github.com/huntresslabs/evading-autoruns)),
  so this add-on offers no option to do it.
- **Every CSV column is written, dynamically.** New Autoruns columns
  appear in the events without a code change, and the `Key : Value`
  layout keeps existing parsers working.
- **UTF-8 handled, UTF-16 detected.** The `-o` file from autorunsc 14.3 is
  UTF-8 without a BOM (observed on Windows 11 24H2; Microsoft documents
  the CSV output but not its encoding), so non-ASCII paths and descriptions
  survive intact; a UTF-16 BOM is detected as well. CI proves the parser
  side with a UTF-8 [fixture](https://github.com/spydisec/WinLogKit/blob/main/tests/fixtures/autoruns-sample.csv)
  in [check 8](https://github.com/spydisec/WinLogKit/blob/main/tests/Invoke-KitChecks.ps1).
- **Run health is an event, not a hope.** A summary (100) or failure (101)
  event every run, a non-zero `autorunsc` exit code treated as failure, and
  a bounded wait that kills a wedged scan - "onboarded" means
  health-monitored.
- **The binary is verified before it runs as SYSTEM.** Whatever its
  origin, its Authenticode signature must be Valid and Microsoft's, or the
  install stops. Program Files (or the Windows folder) only, never a
  user-writable path.
- **The log is created and sized at install.** A log created through the
  .NET API defaults to
  [512 KB](https://learn.microsoft.com/dotnet/api/system.diagnostics.eventlog.maximumkilobytes),
  which one run exceeds; retention is overwrite-as-needed, per the kit's
  never-do list.
- **PowerShell 7 clean.** Events are written through
  `System.Diagnostics.EventLog`, because the `*-EventLog` cmdlets exist
  only in [Windows PowerShell 5.1](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/write-eventlog?view=powershell-5.1).
  The task itself uses `powershell.exe` since it is always present.
- **`-WhatIf`, `-Status`, `-Uninstall`, `-RunNow`.** See before doing,
  prove it works, leave cleanly.

### Credits and licences

The idea and the event-log design come from Palantir's
[AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)
(MIT, 2018) - this is WinLogKit's own implementation of it, keeping the
same log name, source and message layout so content written for the
original keeps working. The MIT notice is reproduced in
`addons\AutorunsToWinEventLog\LICENSE-Palantir.md`; the add-on itself is
MIT like the rest of the kit. Autoruns is Microsoft software under the
[Sysinternals licence terms](https://learn.microsoft.com/sysinternals/license-terms);
it is never vendored in this repository, and the scheduled task passes
`-accepteula` on your behalf - read the terms before deploying.
