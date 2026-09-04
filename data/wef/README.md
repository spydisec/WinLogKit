# data/wef - WEF filter data

## audit_subcategory_events.csv

The complete list of Security event IDs each advanced audit policy
subcategory in the kit's settings table can emit, plus the Eventlog-service
events that are always on (1100, 1102, 1104, 1105, 1108; `Guid` = `ALWAYS`).

| Column | Meaning |
|---|---|
| `Guid` | Audit subcategory GUID as used by `auditpol` and the settings table (`ALWAYS` for the Eventlog-service rows) |
| `Subcategory` | Display name from the settings table |
| `EventID` | One Security event ID the subcategory can produce |
| `SourceUrl` | The Microsoft Learn page the ID was read from |
| `Fetched` | Date the page was read |

**Source:** Microsoft's per-subcategory pages under
<https://learn.microsoft.com/windows/security/threat-protection/auditing/>,
each of which lists the subcategory's events as `NNNN (S/F): description`.
The rows are extracted by `tools\Update-AuditSubcategoryEvents.ps1`, which
is the only thing that fetches; the kit reads this file offline.

**Why it exists:** `New-WefSubscription.ps1 -Filter Baseline` builds the
Security-channel XPath from the subcategories a baseline enables. That
filter must forward *every* event those subcategories can produce, or it
silently drops events the baseline deliberately turned on. The ATT&CK event
map in `data/attack/` is curated for detection value, not completeness, so
it is deliberately not used for this.

**Supplement:** a few events Microsoft documents in its downloadable
[security auditing and monitoring reference](https://www.microsoft.com/download/details.aspx?id=52630)
spreadsheet are missing from the Learn subcategory pages (Certification
Services 4899 and 4900 at the time of writing). The tool adds those from a
short sourced list in the script, with that download page as `SourceUrl`,
so the snapshot stays one CSV with a source on every row.

**Refresh:** run the tool, review the diff (Microsoft occasionally adds or
reclassifies an event), commit. `tests\Invoke-KitChecks.ps1` fails if any
subcategory in the settings table has no rows here.
