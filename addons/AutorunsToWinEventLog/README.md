# AutorunsToWinEventLog (add-on)

Daily scheduled task that runs Sysinternals `autorunsc` and writes every
autostart entry into a dedicated **Autoruns** event log (Event ID 1 per
entry, 100 = run summary, 101 = failure), so persistence hunting rides the
same WEF/AMA pipeline as the rest of the kit.

**This is an optional add-on, not part of the native baseline.** It depends
on a Sysinternals binary, which the kit's core deliberately does not. It
exists because registry autostart locations are the one Persistence gap
native auditing cannot close without per-key SACLs.

From an elevated prompt **in this folder** (`addons\AutorunsToWinEventLog`):

```powershell
.\Install-AutorunsToWinEventLog.ps1 -Download -WhatIf     # see every step
.\Install-AutorunsToWinEventLog.ps1 -Download -RunNow     # install + first run
.\Install-AutorunsToWinEventLog.ps1 -Status               # verify
.\Install-AutorunsToWinEventLog.ps1 -Uninstall            # remove (log kept)
```

Full documentation: <https://spydisec.github.io/WinLogKit/addons/>

Inspired by Palantir's AutorunsToWinEventLog (MIT, notice in
[LICENSE-Palantir.md](LICENSE-Palantir.md)); log name, source and message
layout stay compatible with it.
