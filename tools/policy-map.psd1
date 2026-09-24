# Settings-table item -> how to deliver it by policy: the Intune Settings
# catalog / Policy CSP and the Group Policy path. Read by
# tools\Export-PolicyTables.ps1 (docs\intune-csp.md, docs\gpo-paths.md).
# Curated by hand from Microsoft's documentation; every name below appears
# on the cited page (Doc = page under
# https://learn.microsoft.com/windows/client-management/mdm/). The
# self-checks fail if a kit item is missing from here, so a new setting
# can't slip through unmapped.
#
# Group Policy paths are relative to Computer Configuration > Policies.
@{
    # Advanced audit policy: the Group Policy folder, and the category
    # folder under it by the Audit CSP's prefix (policy-csp-audit).
    AuditFolder     = 'Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies'
    AuditCategories = @{
        AccountLogon       = 'Account Logon'
        AccountLogonLogoff = 'Logon/Logoff'
        AccountManagement  = 'Account Management'
        DetailedTracking   = 'Detailed Tracking'
        DSAccess           = 'DS Access'
        ObjectAccess       = 'Object Access'
        PolicyChange       = 'Policy Change'
        PrivilegeUse       = 'Privilege Use'
        System             = 'System'
    }

    # Audit subcategory GUID -> Audit CSP and its Group Policy name.
    # Values are derived: 1 Success, 2 Failure, 3 Success+Failure.
    Audit = @{
        '0CCE923F-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogon_AuditCredentialValidation'; Gp = 'Audit Credential Validation' }   # Credential Validation
        '0CCE9242-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogon_AuditKerberosAuthenticationService'; Gp = 'Audit Kerberos Authentication Service' }   # Kerberos Authentication Service
        '0CCE9240-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogon_AuditKerberosServiceTicketOperations'; Gp = 'Audit Kerberos Service Ticket Operations' }   # Kerberos Service Ticket Operations
        '0CCE9236-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountManagement_AuditComputerAccountManagement'; Gp = 'Audit Computer Account Management' }   # Computer Account Management
        '0CCE9238-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountManagement_AuditDistributionGroupManagement'; Gp = 'Audit Distribution Group Management' }   # Distribution Group Management
        '0CCE923A-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountManagement_AuditOtherAccountManagementEvents'; Gp = 'Audit Other Account Management Events' }   # Other Account Management Events
        '0CCE9237-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountManagement_AuditSecurityGroupManagement'; Gp = 'Audit Security Group Management' }   # Security Group Management
        '0CCE9235-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountManagement_AuditUserAccountManagement'; Gp = 'Audit User Account Management' }   # User Account Management
        '0CCE9248-69AE-11D9-BED3-505054503030' = @{ Csp = 'DetailedTracking_AuditPNPActivity'; Gp = 'Audit PNP Activity' }   # Plug and Play
        '0CCE922B-69AE-11D9-BED3-505054503030' = @{ Csp = 'DetailedTracking_AuditProcessCreation'; Gp = 'Audit Process Creation' }   # Process Creation
        '0CCE922E-69AE-11D9-BED3-505054503030' = @{ Csp = 'DetailedTracking_AuditRPCEvents'; Gp = 'Audit RPC Events' }   # RPC Events
        '0CCE923B-69AE-11D9-BED3-505054503030' = @{ Csp = 'DSAccess_AuditDirectoryServiceAccess'; Gp = 'Audit Directory Service Access' }   # Directory Service Access
        '0CCE923C-69AE-11D9-BED3-505054503030' = @{ Csp = 'DSAccess_AuditDirectoryServiceChanges'; Gp = 'Audit Directory Service Changes' }   # Directory Service Changes
        '0CCE9217-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogonLogoff_AuditAccountLockout'; Gp = 'Audit Account Lockout' }   # Account Lockout
        '0CCE9216-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogonLogoff_AuditLogoff'; Gp = 'Audit Logoff' }   # Logoff
        '0CCE9215-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogonLogoff_AuditLogon'; Gp = 'Audit Logon' }   # Logon
        '0CCE921C-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogonLogoff_AuditOtherLogonLogoffEvents'; Gp = 'Audit Other Logon Logoff Events' }   # Other Logon/Logoff Events
        '0CCE921B-69AE-11D9-BED3-505054503030' = @{ Csp = 'AccountLogonLogoff_AuditSpecialLogon'; Gp = 'Audit Special Logon' }   # Special Logon
        '0CCE9221-69AE-11D9-BED3-505054503030' = @{ Csp = 'ObjectAccess_AuditCertificationServices'; Gp = 'Audit Certification Services' }   # Certification Services
        '0CCE9224-69AE-11D9-BED3-505054503030' = @{ Csp = 'ObjectAccess_AuditFileShare'; Gp = 'Audit File Share' }   # File Share
        '0CCE9226-69AE-11D9-BED3-505054503030' = @{ Csp = 'ObjectAccess_AuditFilteringPlatformConnection'; Gp = 'Audit Filtering Platform Connection' }   # Filtering Platform Connection
        '0CCE9227-69AE-11D9-BED3-505054503030' = @{ Csp = 'ObjectAccess_AuditOtherObjectAccessEvents'; Gp = 'Audit Other Object Access Events' }   # Other Object Access Events
        '0CCE9245-69AE-11D9-BED3-505054503030' = @{ Csp = 'ObjectAccess_AuditRemovableStorage'; Gp = 'Audit Removable Storage' }   # Removable Storage
        '0CCE9220-69AE-11D9-BED3-505054503030' = @{ Csp = 'ObjectAccess_AuditSAM'; Gp = 'Audit SAM' }   # SAM
        '0CCE922F-69AE-11D9-BED3-505054503030' = @{ Csp = 'PolicyChange_AuditPolicyChange'; Gp = 'Audit Policy Change' }   # Audit Policy Change
        '0CCE9230-69AE-11D9-BED3-505054503030' = @{ Csp = 'PolicyChange_AuditAuthenticationPolicyChange'; Gp = 'Audit Authentication Policy Change' }   # Authentication Policy Change
        '0CCE9234-69AE-11D9-BED3-505054503030' = @{ Csp = 'PolicyChange_AuditOtherPolicyChangeEvents'; Gp = 'Audit Other Policy Change Events' }   # Other Policy Change Events
        '0CCE9228-69AE-11D9-BED3-505054503030' = @{ Csp = 'PrivilegeUse_AuditSensitivePrivilegeUse'; Gp = 'Audit Sensitive Privilege Use' }   # Sensitive Privilege Use
        '0CCE9213-69AE-11D9-BED3-505054503030' = @{ Csp = 'System_AuditIPsecDriver'; Gp = 'Audit IPsec Driver' }   # IPsec Driver
        '0CCE9210-69AE-11D9-BED3-505054503030' = @{ Csp = 'System_AuditSecurityStateChange'; Gp = 'Audit Security State Change' }   # Security State Change
        '0CCE9211-69AE-11D9-BED3-505054503030' = @{ Csp = 'System_AuditSecuritySystemExtension'; Gp = 'Audit Security System Extension' }   # Security System Extension
        '0CCE9212-69AE-11D9-BED3-505054503030' = @{ Csp = 'System_AuditSystemIntegrity'; Gp = 'Audit System Integrity' }   # System Integrity
        '0CCE9214-69AE-11D9-BED3-505054503030' = @{ Csp = 'System_AuditOtherSystemEvents'; Gp = 'Audit Other System Events' }   # Other System Events
    }

    # Registry item Id -> CSP (Csp, CspValue, Doc) and Group Policy (Gp,
    # GpValue). An item without one of them carries NoCsp / NoGp instead:
    # the reason, shown on the page.
    Registry = @{
        CmdLineAudit       = @{ Csp = 'ADMX_AuditSettings/IncludeCmdLine'; CspValue = 'Enabled'; Doc = 'policy-csp-admx-auditsettings'
                                Gp = 'Administrative Templates > System > Audit Process Creation > Include command line in process creation events'; GpValue = 'Enabled' }
        ScriptBlock64      = @{ Csp = 'WindowsPowerShell/TurnOnPowerShellScriptBlockLogging'; CspValue = 'Enabled'; Doc = 'policy-csp-windowspowershell'
                                Gp = 'Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging'; GpValue = 'Enabled' }
        ScriptBlock32      = @{ NoCsp = 'The 32-bit (WOW64) copy of the script block policy has no CSP of its own.'
                                NoGp = 'No Administrative Template writes the 32-bit (WOW64) copy. Use Group Policy Preferences > Windows Settings > Registry, or LGPO with the GPO pack''s registry.txt.' }
        ModuleLogging64    = @{ Csp = 'ADMX_PowerShellExecutionPolicy/EnableModuleLogging'; CspValue = 'Enabled'; Doc = 'policy-csp-admx-powershellexecutionpolicy'
                                Gp = 'Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging'; GpValue = 'Enabled' }
        ModuleLogging32    = @{ NoCsp = 'The 32-bit (WOW64) copy of the module logging policy has no CSP of its own.'
                                NoGp = 'No Administrative Template writes the 32-bit (WOW64) copy. Use Group Policy Preferences > Windows Settings > Registry, or LGPO with the GPO pack''s registry.txt.' }
        ModuleNames64      = @{ Csp = 'ADMX_PowerShellExecutionPolicy/EnableModuleLogging'; CspValue = 'Module names: *'; Doc = 'policy-csp-admx-powershellexecutionpolicy'
                                Gp = 'Administrative Templates > Windows Components > Windows PowerShell > Turn on Module Logging'; GpValue = 'Module Names (Show...): *' }
        ModuleNames32      = @{ NoCsp = 'The 32-bit (WOW64) copy of the module list has no CSP of its own.'
                                NoGp = 'No Administrative Template writes the 32-bit (WOW64) copy. Use Group Policy Preferences > Windows Settings > Registry, or LGPO with the GPO pack''s registry.txt.' }
        PS7ScriptBlock64   = @{ NoCsp = 'No built-in CSP for PowerShell 7 policy. Importing its ADMX as a custom template may be blocked by the registry locations Intune allows for imported ADMX.'
                                Gp = 'Administrative Templates > PowerShell Core > Turn on PowerShell Script Block Logging'; GpValue = 'Enabled, with "Use Windows PowerShell Policy setting." ticked. Needs PowerShell 7''s own template in the central store (see the note above).' }
        PS7ScriptBlock32   = @{ NoCsp = 'No built-in CSP for PowerShell 7 policy (32-bit copy).'
                                NoGp = 'No Administrative Template writes the 32-bit (WOW64) copy. Use Group Policy Preferences > Windows Settings > Registry, or LGPO with the GPO pack''s registry.txt.' }
        PS7ModuleLogging64 = @{ NoCsp = 'No built-in CSP for PowerShell 7 policy. Importing its ADMX as a custom template may be blocked by the registry locations Intune allows for imported ADMX.'
                                Gp = 'Administrative Templates > PowerShell Core > Turn on Module Logging'; GpValue = 'Enabled, with "Use Windows PowerShell Policy setting." ticked. Needs PowerShell 7''s own template in the central store (see the note above).' }
        PS7ModuleLogging32 = @{ NoCsp = 'No built-in CSP for PowerShell 7 policy (32-bit copy).'
                                NoGp = 'No Administrative Template writes the 32-bit (WOW64) copy. Use Group Policy Preferences > Windows Settings > Registry, or LGPO with the GPO pack''s registry.txt.' }
        NtlmOutboundAudit  = @{ NoCsp = 'A CSP exists (LocalPoliciesSecurityOptions/NetworkSecurity_RestrictNTLM_OutgoingNTLMTrafficToRemoteServers), but Microsoft lists its value 1 as "Deny all domain accounts", not the registry''s "Audit all". Setting 1 through the CSP could block NTLM, so don''t set it in Intune; Group Policy or Enable-LoggingBaseline.ps1 sets it correctly.'
                                Gp = 'Windows Settings > Security Settings > Local Policies > Security Options > Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers'; GpValue = 'Audit all' }
        NtlmInboundAudit   = @{ Csp = 'LocalPoliciesSecurityOptions/NetworkSecurity_RestrictNTLM_AuditIncomingNTLMTraffic'; CspValue = '2 (enable auditing for all accounts)'; Doc = 'policy-csp-localpoliciessecurityoptions'
                                Gp = 'Windows Settings > Security Settings > Local Policies > Security Options > Network security: Restrict NTLM: Audit Incoming NTLM Traffic'; GpValue = 'Enable auditing for all accounts' }
        ForceSubcategoryAudit = @{ Csp = 'LocalPoliciesSecurityOptions/Audit_ForceAuditPolicySubcategorySettingsToOverrideAuditPolicyCategorySettings'; CspValue = '1 (Enabled; Windows 11 22H2 with KB5053657, 24H2 and later)'; Doc = 'policy-csp-localpoliciessecurityoptions'
                                Gp = 'Windows Settings > Security Settings > Local Policies > Security Options > Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings'; GpValue = 'Enabled' }
        NtlmDomainAudit    = @{ NoCsp = 'No CSP. Domain controllers only; set it by GPO on the DCs.'
                                Gp = 'Windows Settings > Security Settings > Local Policies > Security Options > Network security: Restrict NTLM: Audit NTLM authentication in this domain'; GpValue = 'Enable all' }
    }

    # SMB audit item Id -> CSP and Group Policy (Windows 11 24H2 and
    # Windows Server 2025 onwards, per Microsoft's CSP pages).
    Smb = @{
        AuditClientDoesNotSupportEncryption = @{ Csp = 'LanmanServer/AuditClientDoesNotSupportEncryption'; Doc = 'policy-csp-lanmanserver'; Gp = 'Administrative Templates > Network > Lanman Server > Audit client does not support encryption' }
        AuditClientDoesNotSupportSigning    = @{ Csp = 'LanmanServer/AuditClientDoesNotSupportSigning'; Doc = 'policy-csp-lanmanserver'; Gp = 'Administrative Templates > Network > Lanman Server > Audit client does not support signing' }
        AuditServerDoesNotSupportEncryption = @{ Csp = 'LanmanWorkstation/AuditServerDoesNotSupportEncryption'; Doc = 'policy-csp-lanmanworkstation'; Gp = 'Administrative Templates > Network > Lanman Workstation > Audit server does not support encryption' }
        AuditServerDoesNotSupportSigning    = @{ Csp = 'LanmanWorkstation/AuditServerDoesNotSupportSigning'; Doc = 'policy-csp-lanmanworkstation'; Gp = 'Administrative Templates > Network > Lanman Workstation > Audit server does not support signing' }
    }

    # Channel -> maximum size CSP (policy-csp-eventlogservice) and the
    # Event Log Service template folder. Only the classic logs have one.
    # Values are the kit target in KB, the unit both take.
    Channels = @{
        'Application' = @{ Csp = 'EventLogService/SpecifyMaximumFileSizeApplicationLog'; Gp = 'Administrative Templates > Windows Components > Event Log Service > Application > Specify the maximum log file size (KB)' }
        'Security'    = @{ Csp = 'EventLogService/SpecifyMaximumFileSizeSecurityLog'; Gp = 'Administrative Templates > Windows Components > Event Log Service > Security > Specify the maximum log file size (KB)' }
        'System'      = @{ Csp = 'EventLogService/SpecifyMaximumFileSizeSystemLog'; Gp = 'Administrative Templates > Windows Components > Event Log Service > System > Specify the maximum log file size (KB)' }
    }
}