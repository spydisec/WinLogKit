# =============================================================================
# LoggingBaseline.Settings.ps1
# Shared settings table for Enable-LoggingBaseline.ps1 and Test-LoggingBaseline.ps1
#
# This is the single source of truth for the kit. Both the enable script and
# the verification script dot-source this file, so they can never disagree
# about what "correct" looks like. If you change a setting, change it here.
#
# Source baselines (extracted 2026-08-31):
#   - Yamato Security, EnableWindowsLogSettings
#     https://github.com/Yamato-Security/EnableWindowsLogSettings
#     (README.md, ConfiguringSecurityLogAuditPolicies.md,
#      YamatoSecurityConfigureWinEventLogs.bat)
#   - Yamato Security, WELA v2.1.0 (WELA.ps1 configure command)
#     https://github.com/Yamato-Security/WELA
#
# Deliberate deviations from those sources are marked "DEVIATION" with the
# reason. Nothing here requires Sysmon or any third party tooling.
#
# Field meanings:
#   Tier       - Core       : applied/tested by default
#                HighVolume : material event volume or performance impact.
#                             Only applied with -IncludeHighVolume so a human
#                             decides, not the script.
#                Optional   : recommended by the sources but situational.
#                             Only applied with -IncludeOptional.
#   Scope      - All | DomainController. DomainController items are skipped
#                (NOT APPLICABLE) on standalone and member servers.
#   Condition  - extra runtime requirement, e.g. 'ADCS' = only when the
#                Certificate Services role is installed.
#   Categories - which behaviour categories the item satisfies.
#                Used for the per-category PASS/FAIL rollup in the test script.
#
# PowerShell 5.1 compatible. No external module dependencies.
#
# -----------------------------------------------------------------------------
# STABILITY SAFETY - settings this kit deliberately NEVER touches, because
# they can hang, halt or lock out a server:
#
#   - CrashOnAuditFail / "Audit: Shut down system immediately if unable to log
#     security audits" (HKLM\SYSTEM\CurrentControlSet\Control\Lsa\CrashOnAuditFail).
#     With this on, a full Security log halts the machine with
#     STOP C0000244 {Audit Failed}, and until reset only Administrators can log
#     on (breaks IIS, AD replication, everything using non-admin logons).
#     https://learn.microsoft.com/troubleshoot/developer/webapps/iis/health-diagnostic-performance/users-cannot-access-web-sites-when-log-full
#   - "Do not overwrite events" retention (LogMode = Retain). Logging silently
#     stops when the log fills; combined with CrashOnAuditFail it crashes the
#     host. Test-LoggingBaseline flags Retain mode as a FAIL.
#   - "Audit the access of global system objects" (AuditBaseObjects) and
#     Global Object Access Auditing - blanket SACLs on all kernel/file/registry
#     objects; extreme volume and measurable performance degradation.
#   - Blanket File System / Registry SACLs - per-object auditing is a scoped
#     design decision, never a default.
#   - The kit also never SHRINKS a log, never reboots, and never restarts a
#     service.
# -----------------------------------------------------------------------------
#
# Optional 'Risk' field on items below: a plain-language stability/performance
# note, shown by New-LoggingBaseline.ps1 so selections are made with eyes open.
# Microsoft rates the WFP subcategories' volume as High; module logging has a
# measurable PowerShell performance cost on script-heavy servers.
# =============================================================================

Set-StrictMode -Version 2.0

# The 16 behaviour categories, in fixed display order.
$script:BaselineCategories = @(
    'Authentication'
    'Execution'
    'Account and access change'
    'Privilege use'
    'Logging tampered with'
    'Software and service install'
    'Remote access'
    'Scheduled and automated tasks'
    'Scripting and command line'
    'Persistence'
    'Removable and external devices'
    'Blocked and denied activity'
    'Directory and identity store'
    'File and object access'
    'Certificates and keys'
    'Network flow and sessions'
)

# -----------------------------------------------------------------------------
# 1. EVENT LOG CHANNELS - maximum size and enablement
#
# Sizes follow the Yamato batch script / WELA configure command:
#   1 GB  (1073741824) for Security and the PowerShell logs
#   128 MB (134217728) for the other important operational logs
# The enable script only ever RAISES a size, it never shrinks a log.
# 'MustEnable' channels are disabled out of the box and must be switched on.
# -----------------------------------------------------------------------------
$oneGB   = 1073741824
$mb128   = 134217728

$script:BaselineChannels = @(
    @{ Name = 'Security';                                                               TargetBytes = $oneGB; MustEnable = $false; Tier = 'Core'; DefaultSize = '20 MB'
       Categories = @('Authentication','Execution','Account and access change','Privilege use','Logging tampered with','Directory and identity store','File and object access','Certificates and keys','Network flow and sessions','Scheduled and automated tasks','Removable and external devices')
       Purpose = 'The main audit log. Almost every behaviour category lands here. 1 GB so evidence is not overwritten within days.' }

    @{ Name = 'Microsoft-Windows-PowerShell/Operational';                               TargetBytes = $oneGB; MustEnable = $false; Tier = 'Core'; DefaultSize = '15 MB'
       Categories = @('Scripting and command line','Execution')
       Purpose = 'PowerShell 5.1 module logging (4103) and script block logging (4104) land here. High value, high volume once those are on.' }

    @{ Name = 'Windows PowerShell';                                                     TargetBytes = $oneGB; MustEnable = $false; Tier = 'Core'; DefaultSize = '15 MB'
       Categories = @('Scripting and command line','Execution')
       Purpose = 'Classic PowerShell engine lifecycle log (400/403/600). Older but still used by detections for downgrade attacks.' }

    @{ Name = 'PowerShellCore/Operational';                                             TargetBytes = $oneGB; MustEnable = $false; Tier = 'Core'; DefaultSize = '15 MB'; MayBeAbsent = $true
       Categories = @('Scripting and command line','Execution')
       Purpose = 'PowerShell 7+ equivalent of the Operational log. Only exists if PowerShell 7 is installed - absent is NOT APPLICABLE.' }

    @{ Name = 'System';                                                                 TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '20 MB'
       Categories = @('Software and service install','Persistence','Logging tampered with')
       Purpose = 'Service installs (7045), service stop/start (7036), event log service stop, log cleared (104).' }

    @{ Name = 'Application';                                                            TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '20 MB'
       Categories = @('Software and service install')
       Purpose = 'MSI installs/uninstalls (MsiInstaller 1040/1034), ESENT database access (NTDS.dit dumping), application crashes.' }

    @{ Name = 'Microsoft-Windows-Windows Defender/Operational';                         TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'; MayBeAbsent = $true
       Categories = @('Blocked and denied activity','Logging tampered with')
       Purpose = 'Defender detections, exclusions being added, tamper protection changes, history deletion.' }

    @{ Name = 'Microsoft-Windows-Bits-Client/Operational';                              TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Execution','Persistence')
       Purpose = 'BITS transfer jobs. bitsadmin.exe is a common living-off-the-land download/execute channel.' }

    @{ Name = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall';     TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity','Network flow and sessions')
       Purpose = 'Firewall rules added, modified or deleted. Malware adds rules to let C2 traffic through.' }

    @{ Name = 'Microsoft-Windows-NTLM/Operational';                                     TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Authentication')
       Purpose = 'Outgoing NTLM usage, populated once the NTLM audit registry values below are set. Needed to plan NTLM retirement.' }

    @{ Name = 'Microsoft-Windows-Security-Mitigations/KernelMode';                      TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity')
       Purpose = 'Exploit protection / mitigation events (kernel mode).' }

    @{ Name = 'Microsoft-Windows-Security-Mitigations/UserMode';                        TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity')
       Purpose = 'Exploit protection / mitigation events (user mode).' }

    @{ Name = 'Microsoft-Windows-PrintService/Admin';                                   TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Software and service install')
       Purpose = 'Print service errors, including failed driver installs (PrintNightmare class attacks).' }

    @{ Name = 'Microsoft-Windows-PrintService/Operational';                             TargetBytes = $mb128; MustEnable = $true;  Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Software and service install')
       Purpose = 'Print driver installs and print jobs. DISABLED by default so must be enabled. Note: the Yamato batch sizes this log but never enables it - the kit fixes that.' }

    @{ Name = 'Microsoft-Windows-SmbClient/Security';                                   TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '8 MB'
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'Outbound SMB session failures, rejected guest logons, hidden share mounts.' }

    @{ Name = 'Microsoft-Windows-AppLocker/EXE and DLL';                                TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity','Execution')
       Purpose = 'AppLocker allow/deny decisions for executables and DLLs. Only populates if AppLocker policy is deployed.' }

    @{ Name = 'Microsoft-Windows-AppLocker/MSI and Script';                             TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity','Execution','Scripting and command line')
       Purpose = 'AppLocker decisions for installers and scripts.' }

    @{ Name = 'Microsoft-Windows-AppLocker/Packaged app-Deployment';                    TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity','Software and service install')
       Purpose = 'AppLocker decisions for packaged (Store) app deployment.' }

    @{ Name = 'Microsoft-Windows-AppLocker/Packaged app-Execution';                     TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity','Execution')
       Purpose = 'AppLocker decisions for packaged (Store) app execution.' }

    @{ Name = 'Microsoft-Windows-CodeIntegrity/Operational';                            TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Blocked and denied activity','Software and service install')
       Purpose = 'Driver loads blocked by code integrity - a failed malicious driver load shows up here.' }

    @{ Name = 'Microsoft-Windows-Diagnosis-Scripted/Operational';                       TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Scripting and command line','Execution')
       Purpose = 'Diagnostic (diagcab) package execution - abused for social engineering delivery.' }

    @{ Name = 'Microsoft-Windows-DriverFrameworks-UserMode/Operational';                TargetBytes = $mb128; MustEnable = $true;  Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Removable and external devices')
       Purpose = 'USB device plug/unplug detail. DISABLED by default so must be enabled.' }

    @{ Name = 'Microsoft-Windows-WMI-Activity/Operational';                             TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Execution','Persistence','Scheduled and automated tasks')
       Purpose = 'WMI operations. WMI event subscriptions are a common fileless persistence mechanism.' }

    @{ Name = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';     TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Remote access')
       Purpose = 'RDP session connect/disconnect/reconnect (21/24/25) with source address - survives Security log clearing.' }

    @{ Name = 'Microsoft-Windows-TaskScheduler/Operational';                            TargetBytes = $mb128; MustEnable = $true;  Tier = 'Core'; DefaultSize = '1 MB'
       Categories = @('Scheduled and automated tasks','Persistence')
       Purpose = 'Task registration, updates and execution. DISABLED by default so must be enabled. Tasks are a top persistence mechanism.' }

    @{ Name = 'Microsoft-Windows-SMBServer/Audit';                                      TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '8 MB'; MayBeAbsent = $true
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'SMB server audit events, including Windows Server 2025 signing/encryption capability auditing (3021/3022) - identifies clients that cannot do SMB signing or encryption before you enforce it.' }

    @{ Name = 'Microsoft-Windows-SmbClient/Audit';                                      TargetBytes = $mb128; MustEnable = $false; Tier = 'Core'; DefaultSize = '8 MB'; MayBeAbsent = $true
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'SMB client audit events, including Windows Server 2025 signing/encryption capability auditing (31998/31999) and NTLM-blocking diagnostics.' }

    @{ Name = 'Microsoft-Windows-Crypto-DPAPI/Debug';                                   TargetBytes = $mb128; MustEnable = $true;  Tier = 'Optional'; DefaultSize = '1 MB'; MayBeAbsent = $true
       Categories = @('Certificates and keys')
       Purpose = 'DPAPI key operations. Added by WELA v2.1 configure. A debug-class channel, so Optional: enable only if DPAPI theft (e.g. Mimikatz backup key export) is a monitored scenario.'
       Risk = 'Debug-class channels carry a small constant tracing overhead and are not designed for always-on production use. Enable deliberately, not by default.' }
)

# -----------------------------------------------------------------------------
# 2. ADVANCED AUDIT POLICY SUBCATEGORIES
#
# GUIDs are used instead of names so the scripts work on any OS language
# (same approach as the Yamato batch). Success/Failure flags are the Yamato
# recommendation. Items commented out of the Yamato batch (Process Termination,
# Token Right Adjusted, Group Membership, Detailed File Share, File System,
# Filtering Platform Packet Drop, Kernel Object, Registry, Authorization
# Policy Change, Filtering Platform Policy Change, MPSSVC Rule-Level Policy
# Change) are deliberately NOT here - see README "Known gaps".
# -----------------------------------------------------------------------------
$script:BaselineAuditSubcategories = @(
    # --- Account Logon ---
    @{ Name = 'Credential Validation';                Guid = '0CCE923F-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Authentication')
       Purpose = 'NTLM authentication results (4776). Catches password spraying and username guessing over NTLM.' }

    @{ Name = 'Kerberos Authentication Service';      Guid = '0CCE9242-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'DomainController'; Tier = 'Core'
       Categories = @('Authentication','Directory and identity store')
       Purpose = 'Kerberos TGT requests (4768) and pre-auth failures (4771). Only generated on domain controllers.' }

    @{ Name = 'Kerberos Service Ticket Operations';   Guid = '0CCE9240-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'DomainController'; Tier = 'Core'
       Categories = @('Authentication')
       Purpose = 'Service ticket requests (4769) - the Kerberoasting detection event. Only generated on domain controllers.' }

    # --- Account Management ---
    @{ Name = 'Computer Account Management';          Guid = '0CCE9236-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'DomainController'; Tier = 'Core'
       Categories = @('Account and access change','Directory and identity store')
       Purpose = 'Computer accounts created/changed/deleted (4741-4743). DCShadow detection uses 4742. DC only.' }

    @{ Name = 'Distribution Group Management';        Guid = '0CCE9238-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'DomainController'; Tier = 'Core'
       Categories = @('Account and access change')
       Purpose = 'Distribution group lifecycle. In the WELA configure baseline (not the older batch). DC only in practice.' }

    @{ Name = 'Other Account Management Events';      Guid = '0CCE923A-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Account and access change')
       Purpose = 'Password hash access (4782) and password policy API checks (4793). Rare, low volume, high signal.' }

    @{ Name = 'Security Group Management';            Guid = '0CCE9237-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Account and access change')
       Purpose = 'Group create/change/delete and membership changes (4727-4764). "User added to local Administrators" (4732) lives here.' }

    @{ Name = 'User Account Management';              Guid = '0CCE9235-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Account and access change')
       Purpose = 'User accounts created/enabled/changed/deleted, password resets, lockouts (4720-4767). Backdoor account detection.' }

    # --- Detailed Tracking ---
    @{ Name = 'Plug and Play';                        Guid = '0CCE9248-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Removable and external devices')
       Purpose = 'New external device connected (6416), device install blocked/allowed (6419-6424). USB and rogue-device tracking.' }

    @{ Name = 'Process Creation';                     Guid = '0CCE922B-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'HighVolume'
       Categories = @('Execution','Scripting and command line','Persistence')
       Purpose = 'Process creation (4688). The single highest value audit setting - roughly half of all Sigma rules need it - but HIGH VOLUME. Pair with the command line registry value below.'
       Risk = 'Event volume scales with process churn; heaviest on RDS/Citrix and build servers. Disk and SIEM cost, not a stability risk.' }

    @{ Name = 'RPC Events';                           Guid = '0CCE922E-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'Inbound RPC connections (5712). Rare event in practice; Microsoft warns it can be busy on heavy RPC servers.'
       Risk = 'Usually near-silent, but Microsoft flags high volume on RPC-heavy servers (Exchange, some cluster roles). Deselect if 5712 floods.' }

    # --- DS Access ---
    @{ Name = 'Directory Service Access';             Guid = '0CCE923B-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'DomainController'; Tier = 'Core'
       Categories = @('Directory and identity store')
       Purpose = 'AD object access (4661/4662). DCSync and DPAPI backup key theft detection. DC only; needs SACLs on AD objects for full value.' }

    @{ Name = 'Directory Service Changes';            Guid = '0CCE923C-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'DomainController'; Tier = 'Core'
       Categories = @('Directory and identity store','Persistence')
       Purpose = 'AD object modifications with old/new values (5136-5141). AD backdoor and DCShadow detection. DC only.' }

    # --- Logon/Logoff ---
    @{ Name = 'Account Lockout';                      Guid = '0CCE9217-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Authentication','Blocked and denied activity')
       Purpose = 'Logons failing because the account is locked out (4625 / 0xC0000234).' }

    @{ Name = 'Logoff';                               Guid = '0CCE9216-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Authentication')
       Purpose = 'Session end (4634/4647). Needed to bound session duration in investigations.' }

    @{ Name = 'Logon';                                Guid = '0CCE9215-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Authentication','Remote access')
       Purpose = 'Logon success/failure and explicit-credential logons (4624/4625/4648). Logon type field distinguishes console, network, RDP.' }

    @{ Name = 'Other Logon/Logoff Events';            Guid = '0CCE921C-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Authentication','Remote access')
       Purpose = 'RDP session reconnect/disconnect (4778/4779), workstation lock/unlock, CredSSP delegation blocks.' }

    @{ Name = 'Special Logon';                        Guid = '0CCE921B-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Privilege use','Authentication')
       Purpose = 'Logons holding admin-equivalent privileges (4672). Cheap way to see privileged sessions without Sensitive Privilege Use volume.' }

    # --- Object Access ---
    @{ Name = 'Certification Services';               Guid = '0CCE9221-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Certificates and keys')
       Purpose = 'AD CS activity including certificate template events (4898/4899, ESC-class template abuse). Harmless when AD CS absent - simply generates nothing.' }

    @{ Name = 'File Share';                           Guid = '0CCE9224-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('File and object access','Remote access')
       Purpose = 'Share connections (5140, ADMIN$ access), share created/modified/deleted (5142-5144). Busy on file servers and DCs.'
       Risk = 'On dedicated file servers and DCs (SYSVOL access) this is a steady event stream. Watch log wrap time during the pilot.' }

    @{ Name = 'Filtering Platform Connection';        Guid = '0CCE9226-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'HighVolume'
       Categories = @('Network flow and sessions','Blocked and denied activity')
       Purpose = 'Per-connection allow/block from Windows Filtering Platform (5156/5157) plus listens and binds. The closest native equivalent to network flow telemetry. HIGH VOLUME.'
       Risk = 'Microsoft rates this volume High. On connection-heavy servers (DCs, web, SQL) it can dominate the Security log and add measurable CPU/disk load; can wrap a 1 GB log in hours. Deploy to a pilot host first.' }

    @{ Name = 'Other Object Access Events';           Guid = '0CCE9227-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Scheduled and automated tasks','Persistence')
       Purpose = 'Scheduled task created/deleted/enabled/disabled/updated (4698-4702) in the Security log. Low volume, high signal.' }

    @{ Name = 'Removable Storage';                    Guid = '0CCE9245-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Removable and external devices','File and object access')
       Purpose = 'Every file access on removable storage (4663), no SACL needed. Volume scales with how much USB storage is actually used.'
       Risk = 'A large file copy to USB generates an event per file access. Low on servers where USB is rare; heavy where USB drives are routine.' }

    @{ Name = 'SAM';                                  Guid = '0CCE9220-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Directory and identity store')
       Purpose = 'Access to local SAM objects (4661). Detects local account/group reconnaissance. Can be busy on DCs - test there first.'
       Risk = 'High event rate on domain controllers. Volume/cost concern only, not stability.' }

    # --- Policy Change ---
    @{ Name = 'Audit Policy Change';                  Guid = '0CCE922F-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Logging tampered with')
       Purpose = 'The audit policy itself being changed (4719), SACLs changed (4715/4907), CrashOnAuditFail changed. Core anti-tamper telemetry.' }

    @{ Name = 'Authentication Policy Change';         Guid = '0CCE9230-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Account and access change','Authentication')
       Purpose = 'Domain/forest trusts added or removed (4706/4707), Kerberos policy changes, logon rights granted (4717).' }

    @{ Name = 'Other Policy Change Events';           Guid = '0CCE9234-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Network flow and sessions','Certificates and keys')
       Purpose = 'WFP filter changes and CNG crypto operations. NOTE: the Yamato guide text says leave off because event 5447 is noisy, but both Yamato scripts enable it. The kit follows the scripts; drop to save volume if 5447 floods.' }

    # --- Privilege Use ---
    @{ Name = 'Sensitive Privilege Use';              Guid = '0CCE9228-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'HighVolume'
       Categories = @('Privilege use')
       Purpose = 'Use of dangerous privileges - SeDebugPrivilege, SeLoadDriverPrivilege, SeTcbPrivilege (4673/4674). Detects credential dumpers and driver loading, but HIGH VOLUME.'
       Risk = 'Known to flood on hosts running backup agents and monitoring software (backup/restore privileges fire constantly). Test on one host per server role before fleet rollout.' }

    # --- System ---
    @{ Name = 'IPsec Driver';                         Guid = '0CCE9213-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Optional'
       Categories = @('Network flow and sessions')
       Purpose = 'IPsec driver events (4960-4963, 4965, 5478-5485) - dropped IPsec packets and driver integrity failures. In Microsoft''s baseline recommendation (and the Microsoft_Client baseline in Yamato''s EventLog-Baseline-Guide) but not in the Yamato set, so Optional: enable where IPsec is actually used.' }

    @{ Name = 'Security State Change';                Guid = '0CCE9210-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Logging tampered with')
       Purpose = 'System start/shutdown and system time changes (4616). Time tampering breaks forensic timelines.' }

    @{ Name = 'Security System Extension';            Guid = '0CCE9211-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Software and service install','Persistence')
       Purpose = 'Service installed (4697) and authentication packages / SSPs registered with LSA (4610/4611/4622). Top-tier persistence telemetry.' }

    @{ Name = 'System Integrity';                     Guid = '0CCE9212-69AE-11D9-BED3-505054503030'; Success = $true; Failure = $true; Scope = 'All';              Tier = 'Core'
       Categories = @('Logging tampered with')
       Purpose = 'Audit events lost (4612), invalid image hashes (5038/6281). Integrity of the logging pipeline itself.' }

    @{ Name = 'Other System Events';                  Guid = '0CCE9214-69AE-11D9-BED3-505054503030'; Success = $false; Failure = $true; Scope = 'All';             Tier = 'Core'
       Categories = @('Logging tampered with','Certificates and keys')
       Purpose = 'Firewall service start/stop and crypto key file operations. Failure-only, matching the Yamato batch (success side is noise). WELA sets Success and Failure; either satisfies the failure requirement.' }
)

# -----------------------------------------------------------------------------
# 3. REGISTRY SETTINGS
#
# All values written under HKLM. 'Kind' is a Microsoft.Win32.RegistryValueKind
# name. 'AbsentOk' items compare as PASS when absent AND value optional.
# -----------------------------------------------------------------------------
$script:BaselineRegistrySettings = @(
    # -- Process command line capture (pairs with the Process Creation subcategory) --
    @{ Id = 'CmdLineAudit'
       Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name = 'ProcessCreationIncludeCmdLine_Enabled'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Execution','Scripting and command line')
       Purpose = 'Adds the full command line to every 4688 process creation event. Most process-based detections need it. CAUTION: command lines can contain passwords typed by admins - handle the Security log as sensitive.'
       Risk = 'No extra event count (enriches 4688), but a privacy/secrets consideration: credentials passed on command lines become log content.' }

    # -- PowerShell script block logging (event 4104) --
    # DEVIATION: the Yamato batch writes only the Wow6432Node path. Group Policy
    # writes the native path, and 64-bit PowerShell reads the native path, so the
    # kit sets BOTH to cover 32-bit and 64-bit hosts.
    @{ Id = 'ScriptBlock64'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Scripting and command line')
       Purpose = 'Logs every PowerShell script block AFTER de-obfuscation (event 4104). Obfuscated malware is logged decoded. Moderate-high volume.'
       Risk = 'Moderate volume and small per-script overhead; generally safe fleet-wide. Large scripts fragment into 32 KB event blocks.' }

    @{ Id = 'ScriptBlock32'
       Path = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Scripting and command line')
       Purpose = 'Same as above for 32-bit PowerShell hosts (the path the Yamato batch sets).' }

    # -- PowerShell module logging (event 4103) --
    @{ Id = 'ModuleLogging64'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Scripting and command line')
       Purpose = 'Logs pipeline execution detail for PowerShell modules (event 4103), including command output. EXTREMELY high volume - a single Mimikatz run produces 2000+ events / ~7 MB.'
       Risk = 'The heaviest setting in the kit. Adds measurable PowerShell execution overhead and huge log volume on script-heavy servers (Exchange management, SCCM, heavy automation). Many teams take script block logging and skip this one.' }

    @{ Id = 'ModuleLogging32'
       Path = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name = 'EnableModuleLogging'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Scripting and command line')
       Purpose = 'Same as above for 32-bit PowerShell hosts.' }

    @{ Id = 'ModuleNames64'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*'; Kind = 'String'; Value = '*'
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Scripting and command line')
       Purpose = 'Wildcard entry meaning "log all modules". Without this, module logging is enabled but logs nothing.' }

    @{ Id = 'ModuleNames32'
       Path = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; Name = '*'; Kind = 'String'; Value = '*'
       Scope = 'All'; Tier = 'HighVolume'; Categories = @('Scripting and command line')
       Purpose = 'Same as above for 32-bit PowerShell hosts.' }

    # -- PowerShell transcription (text files on disk, not event log) --
    @{ Id = 'Transcription64'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'Optional'; Categories = @('Scripting and command line')
       Purpose = 'Writes a text transcript of every PowerShell session to disk. Storage-cheap and survives event log clearing, but transcripts land in user Documents unless OutputDirectory is set. [Output directory to be agreed with the client.]' }

    @{ Id = 'TranscriptionHeader64'
       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableInvocationHeader'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'Optional'; Categories = @('Scripting and command line')
       Purpose = 'Adds a timestamped header per command in transcripts, needed for timeline reconstruction.' }

    @{ Id = 'Transcription32'
       Path = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableTranscripting'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'Optional'; Categories = @('Scripting and command line')
       Purpose = 'Same as above for 32-bit PowerShell hosts.' }

    @{ Id = 'TranscriptionHeader32'
       Path = 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription'; Name = 'EnableInvocationHeader'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'Optional'; Categories = @('Scripting and command line')
       Purpose = 'Same as above for 32-bit PowerShell hosts.' }

    # -- NTLM auditing (populates Microsoft-Windows-NTLM/Operational) --
    # DEVIATION: WELA configure sets RestrictSendingNTLMTraffic = 2, which is
    # "Deny all" - that BLOCKS outgoing NTLM, an enforcement change, not a
    # logging change, and can break connectivity. The kit sets 1 ("Audit all"),
    # which logs the same traffic without blocking anything.
    @{ Id = 'NtlmOutboundAudit'
       Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'RestrictSendingNTLMTraffic'; Kind = 'DWord'; Value = 1
       Scope = 'All'; Tier = 'Core'; Categories = @('Authentication')
       Purpose = 'Audit all outgoing NTLM authentication (1 = audit, nothing blocked). Feeds the NTLM/Operational channel so NTLM retirement can be planned on evidence.' }

    @{ Id = 'NtlmInboundAudit'
       Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; Name = 'AuditReceivingNTLMTraffic'; Kind = 'DWord'; Value = 2
       Scope = 'All'; Tier = 'Core'; Categories = @('Authentication')
       Purpose = 'Audit incoming NTLM authentication for all accounts (2 = all accounts). Audit-only, nothing blocked.' }

    # DEVIATION: WELA sets AuditNTLMInDomain = 2; Microsoft documents 7 as
    # "enable auditing for all NTLM authentication in the domain". Only
    # meaningful on domain controllers.
    @{ Id = 'NtlmDomainAudit'
       Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'; Name = 'AuditNTLMInDomain'; Kind = 'DWord'; Value = 7
       Scope = 'DomainController'; Tier = 'Core'; Categories = @('Authentication')
       Purpose = 'Audit all NTLM authentication passing through this domain controller (7 = all). Audit-only.' }
)

# -----------------------------------------------------------------------------
# 3b. SMB SIGNING/ENCRYPTION AUDITING (Windows Server 2025 / Win 11 24H2+)
#
# New in Windows Server 2025: audit which peers cannot do SMB signing or
# encryption, so enforcement can be planned on evidence instead of breaking
# file shares. Configured via Set-SmbServerConfiguration /
# Set-SmbClientConfiguration (documented by Microsoft in "What's new in
# Windows Server 2025"), not registry or auditpol, so these have their own
# item type. On older OSes the properties do not exist and the scripts report
# NOT APPLICABLE. Events land in the SMBServer/Audit and SmbClient/Audit
# channels sized above. Audit-only: nothing is blocked or enforced.
# -----------------------------------------------------------------------------
$script:BaselineSmbAuditSettings = @(
    @{ Id = 'AuditClientDoesNotSupportEncryption'; Side = 'Server'; Value = $true; Tier = 'Core'; Scope = 'All'
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'SMB server logs clients that cannot do SMB encryption (event 3021 in SMBServer/Audit). Windows Server 2025+ only.' }

    @{ Id = 'AuditClientDoesNotSupportSigning'; Side = 'Server'; Value = $true; Tier = 'Core'; Scope = 'All'
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'SMB server logs clients that cannot do SMB signing (event 3022 in SMBServer/Audit). Windows Server 2025+ only.' }

    @{ Id = 'AuditServerDoesNotSupportEncryption'; Side = 'Client'; Value = $true; Tier = 'Core'; Scope = 'All'
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'SMB client logs servers that cannot do SMB encryption (event 31998 in SmbClient/Audit). Windows Server 2025+ only.' }

    @{ Id = 'AuditServerDoesNotSupportSigning'; Side = 'Client'; Value = $true; Tier = 'Core'; Scope = 'All'
       Categories = @('Remote access','Network flow and sessions')
       Purpose = 'SMB client logs servers that cannot do SMB signing (event 31999 in SmbClient/Audit). Windows Server 2025+ only.' }
)

# -----------------------------------------------------------------------------
# 3c. WEF TRANSPORT DEFAULTS. The subscription-shaping values (ContentFormat,
#     batching, heartbeat, SDDL) are consumed by New-WefSubscription.ps1 and
#     overridable per run via its parameters; the refresh interval and the
#     ForwardedEvents thresholds are guidance/verification values consumed by
#     the setup output and Test-LoggingBaseline -WefRole (not parameters).
# -----------------------------------------------------------------------------
$script:BaselineWefDefaults = @{
    # Events = binary, locale-independent, smaller on the wire (SIEM-friendly).
    # RenderedText adds human-readable message text at higher transport cost.
    ContentFormat = 'Events'
    # Delivery batching: push a batch when either bound is hit. 30s keeps
    # near-real-time visibility; raise for WAN-constrained sources.
    MaxLatencySeconds = 30
    MaxItems = 500
    # Source heartbeat so silently-dead forwarders are noticeable on the
    # collector. Low values add chatter fleet-wide.
    HeartbeatSeconds = 3600
    # Which computers may forward: Microsoft's documented default grants
    # Domain Computers and Network Service.
    AllowedSourceDomainComputersSddl = 'O:NSG:BAD:P(A;;GA;;;DC)(A;;GA;;;NS)S:'
    # How often sources re-read the SubscriptionManager policy (seconds).
    # Lower = faster pickup of subscription changes, more policy chatter.
    SubscriptionRefreshSeconds = 60
    # ForwardedEvents on the collector: verification floor and the size the
    # kit recommends. A collector aggregates whole fleets; an undersized
    # ForwardedEvents log wraps in minutes and loses forwarded evidence.
    ForwardedEventsMinBytes         = 134217728
    ForwardedEventsRecommendedBytes = 1073741824
}

# -----------------------------------------------------------------------------
# 4. AD CS AUDIT FILTER (conditional - only when Certificate Services installed)
#
# Kept separate from plain registry settings because it needs a CertSvc
# service restart to take effect. The enable script sets the value and WARNS;
# it never restarts the service itself (WELA restarts it automatically - the
# kit deliberately does not).
# -----------------------------------------------------------------------------
$script:BaselineAdcsAuditFilter = @{
    Id = 'AdcsAuditFilter'
    # Actual path is HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA name>
    # and is resolved at runtime from the 'Active' value on the Configuration key.
    BasePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'
    Name  = 'AuditFilter'; Kind = 'DWord'; Value = 127
    Scope = 'All'; Tier = 'Core'; Categories = @('Certificates and keys')
    Purpose = 'Turns on all seven AD CS audit event groups (127 = full bitmask) so certificate issuance, template changes and CA configuration changes are logged (4886-4899). REQUIRES a CertSvc service restart to take effect.'
}

# -----------------------------------------------------------------------------
# 5. CATEGORY COVERAGE NOTES - honest statements about what native Windows
# logging can and cannot do per category. Rendered by the test script and
# duplicated in README.md.
# -----------------------------------------------------------------------------
$script:BaselineCategoryNotes = @{
    'Authentication'                 = 'Fully covered natively (Security log + NTLM Operational channel).'
    'Execution'                      = 'Covered by 4688 + command line (HighVolume tier). Without Sysmon there are no file hashes or DLL/image load events - accepted gap.'
    'Account and access change'      = 'Fully covered natively.'
    'Privilege use'                  = 'Covered by Special Logon (Core) and Sensitive Privilege Use (HighVolume tier).'
    'Logging tampered with'          = 'Covered natively (4719, 1102, 104, 4612, service stop events).'
    'Software and service install'   = 'Covered natively (7045, 4697, MsiInstaller, CodeIntegrity, PrintService).'
    'Remote access'                  = 'Covered natively (4624 type 3/10, 4778/4779, TS-LocalSessionManager, SmbClient).'
    'Scheduled and automated tasks'  = 'Fully covered natively (4698-4702 + TaskScheduler Operational).'
    'Scripting and command line'     = 'Covered by PowerShell logging + 4688 command line (HighVolume tier). Non-PowerShell interpreters (cmd, wscript, python) are visible only through 4688 command lines.'
    'Persistence'                    = 'PARTIAL. Services, tasks, WMI and LSA extensions covered. Registry autorun (Run keys, IFEO) monitoring needs the Registry audit subcategory plus per-key SACLs - not in this baseline; native gap without endpoint tooling.'
    'Removable and external devices' = 'Fully covered natively (Plug and Play, Removable Storage, DriverFrameworks-UserMode).'
    'Blocked and denied activity'    = 'Covered natively (Defender, AppLocker, CodeIntegrity, Security-Mitigations, firewall, failed logons). AppLocker channels only populate if an AppLocker policy is deployed.'
    'Directory and identity store'   = 'Covered on domain controllers (DS Access/Changes) and locally via SAM auditing. On a standalone server the DC items are NOT APPLICABLE by design.'
    'File and object access'         = 'PARTIAL. Share-level access covered (5140). Per-file auditing (4663) needs File System subcategory plus SACLs on chosen paths - a per-asset design decision, deliberately not set blanket-wide. Removable storage file access IS fully covered.'
    'Certificates and keys'          = 'Covered where AD CS is installed (Certification Services + AuditFilter). On hosts without AD CS, native visibility is limited to CNG events in Other Policy Change - accepted limitation.'
    'Network flow and sessions'      = 'PARTIAL. Best native option is Filtering Platform Connection 5156/5157 (HighVolume tier). Native logging has no byte counts or flow aggregation - true flow telemetry needs network-layer sources (firewall/NetFlow), outside host scope.'
}
