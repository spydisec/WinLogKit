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
auditing cannot cover without per-key SACLs, and Autoruns is the
long-standing answer to it - but it is a Sysinternals binary, so it lives
here, opt-in, clearly labelled. Be precise about what it gives you: a
**daily inventory** (what is persisted right now, diffable day to day),
not real-time change auditing. A change made and reverted between two
runs is invisible to it; only a registry SACL sees that.

**Origin and credit:** a rewrite of Palantir's
[AutorunsToWinEventLog](https://github.com/palantir/windows-event-forwarding/tree/master/AutorunsToWinEventLog)
(MIT, 2018; the notice is reproduced in the add-on folder). The original is
still widely deployed but has not moved since 2018; this version keeps its
event log name, source and message layout so existing content keeps
working, and fixes the problems its issue tracker and eight years of
Autoruns releases surfaced.

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
the task `AutorunsToWinEventLog`
(daily at 01:00 as SYSTEM, 60-minute limit, runs when next available if
the time was missed). `-DailyAt` and `-LogMaxMB` adjust the defaults.
Everything is idempotent. A custom `-InstallDir` must sit under Program
Files or the Windows folder and grant write rights only to administrators
and SYSTEM - the installer refuses anything else, because a task running
as SYSTEM from a folder a standard user can alter is a privilege
escalation waiting to happen.

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
  query - `<Select Path="Autoruns">*</Select>` - or regenerate with the
  kit's generator once the channel is in your baseline selection. Sources
  need nothing extra: it is a classic log readable by the forwarding
  service.
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

### Deliberate differences from Palantir's original

| Original | This add-on | Why |
|---|---|---|
| `-v -vt` VirusTotal lookups on every run | Not used | Needs internet from every host, slows the run, and sent hashes to a third party by default. Hashes and signature verification are kept, so VT enrichment can happen SIEM-side. |
| stdout redirected to a CSV, read with the default code page | `-o` to a file, read as UTF-8 (UTF-16 auto-detected by BOM) | Observed with autorunsc 14.3 on Windows 11 24H2: the `-o` file is UTF-8 without a BOM and the original's ANSI read mangled every non-ASCII path or description. Microsoft documents the CSV output but not its encoding, so the payload sniffs for a UTF-16 BOM too. CI proves the parser side with a UTF-8 [fixture](https://github.com/spydisec/WinLogKit/blob/main/tests/fixtures/autoruns-sample.csv) in [check 8](https://github.com/spydisec/WinLogKit/blob/main/tests/Invoke-KitChecks.ps1). |
| Hard-wired message fields | Every CSV column written dynamically | New Autoruns columns (PESHA-256, IMP) appear without code changes; layout unchanged for existing parsers. |
| No `-m` (keep Microsoft-signed entries) | Same, and no option to hide them | Attackers persist through Microsoft-signed binaries ([Huntress: evading Autoruns](https://github.com/huntresslabs/evading-autoruns)); Palantir's issue #11 reached the same conclusion. |
| Local group enumeration as Event ID 2 | Dropped | The kit covers group changes natively (4732/4733/4756 ...); mixing two feeds in one log made parsing ambiguous. |
| No run health signal | Events 100 and 101 | "Onboarded" means health-monitored: a SIEM can alert when a host stops reporting or a run fails. |
| Download over HTTPS, no verification | Authenticode must be Valid and signed by Microsoft, or the file is removed | The binary runs as SYSTEM daily. |
| `PROGRA~1` short path in the task action | Quoted full path under Program Files | Same admin-write-only location, without the 8.3 dependency. Never a user-writable folder for a SYSTEM task. |
| Event log created on first run at the classic default size | Created and sized at install (128 MB default, host-configurable via `-LogMaxMB`), overwrite-as-needed | A log created through the .NET API defaults to [512 KB](https://learn.microsoft.com/dotnet/api/system.diagnostics.eventlog.maximumkilobytes), which a single run exceeds; and "do not overwrite" retention is on the kit's never-do list. |
| `Write-EventLog` / `New-EventLog` cmdlets | .NET `System.Diagnostics.EventLog` | Those cmdlets exist only in [Windows PowerShell 5.1](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/write-eventlog?view=powershell-5.1) (the version picker on that page has no PowerShell 7 entry); the .NET API works on both engines. |
| Install only | `-WhatIf`, `-Status`, `-Uninstall`, `-RunNow` | See before doing, prove it works, leave cleanly. |

Not adopted from the original repo's open pull requests: switching the
download to plain HTTP (PR #55) - the signature check makes the transport
less critical, but there is no reason to drop HTTPS.

### Licences

The add-on scripts are MIT (as is the kit, as was Palantir's original -
notice reproduced in `addons\AutorunsToWinEventLog\LICENSE-Palantir.md`).
Autoruns itself is Microsoft software under the
[Sysinternals licence terms](https://learn.microsoft.com/sysinternals/license-terms);
it is never vendored in this repository, and the scheduled task passes
`-accepteula` on your behalf - read the terms before deploying.
