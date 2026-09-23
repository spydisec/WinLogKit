# Settings-table item -> Intune Settings catalog / Policy CSP, for
# tools\Export-CspTable.ps1 (docs\intune-csp.md). Curated by hand from
# Microsoft's Policy CSP reference; every name below appears on the cited
# page. The self-checks fail if a kit item is in neither the mappings nor
# NoCsp, so a new setting can't slip through unmapped.
#
# Doc = the page under https://learn.microsoft.com/windows/client-management/mdm/
@{
    # Audit subcategory GUID -> Audit CSP (policy-csp-audit). Values are
    # derived: 1 Success, 2 Failure, 3 Success+Failure.
    Audit = @{
        '0CCE923F-69AE-11D9-BED3-505054503030' = 'AccountLogon_AuditCredentialValidation'   # Credential Validation
        '0CCE9242-69AE-11D9-BED3-505054503030' = 'AccountLogon_AuditKerberosAuthenticationService'   # Kerberos Authentication Service
        '0CCE9240-69AE-11D9-BED3-505054503030' = 'AccountLogon_AuditKerberosServiceTicketOperations'   # Kerberos Service Ticket Operations
        '0CCE9236-69AE-11D9-BED3-505054503030' = 'AccountManagement_AuditComputerAccountManagement'   # Computer Account Management
        '0CCE9238-69AE-11D9-BED3-505054503030' = 'AccountManagement_AuditDistributionGroupManagement'   # Distribution Group Management
        '0CCE923A-69AE-11D9-BED3-505054503030' = 'AccountManagement_AuditOtherAccountManagementEvents'   # Other Account Management Events
        '0CCE9237-69AE-11D9-BED3-505054503030' = 'AccountManagement_AuditSecurityGroupManagement'   # Security Group Management
        '0CCE9235-69AE-11D9-BED3-505054503030' = 'AccountManagement_AuditUserAccountManagement'   # User Account Management
        '0CCE9248-69AE-11D9-BED3-505054503030' = 'DetailedTracking_AuditPNPActivity'   # Plug and Play
        '0CCE922B-69AE-11D9-BED3-505054503030' = 'DetailedTracking_AuditProcessCreation'   # Process Creation
        '0CCE922E-69AE-11D9-BED3-505054503030' = 'DetailedTracking_AuditRPCEvents'   # RPC Events
        '0CCE923B-69AE-11D9-BED3-505054503030' = 'DSAccess_AuditDirectoryServiceAccess'   # Directory Service Access
        '0CCE923C-69AE-11D9-BED3-505054503030' = 'DSAccess_AuditDirectoryServiceChanges'   # Directory Service Changes
        '0CCE9217-69AE-11D9-BED3-505054503030' = 'AccountLogonLogoff_AuditAccountLockout'   # Account Lockout
        '0CCE9216-69AE-11D9-BED3-505054503030' = 'AccountLogonLogoff_AuditLogoff'   # Logoff
        '0CCE9215-69AE-11D9-BED3-505054503030' = 'AccountLogonLogoff_AuditLogon'   # Logon
        '0CCE921C-69AE-11D9-BED3-505054503030' = 'AccountLogonLogoff_AuditOtherLogonLogoffEvents'   # Other Logon/Logoff Events
        '0CCE921B-69AE-11D9-BED3-505054503030' = 'AccountLogonLogoff_AuditSpecialLogon'   # Special Logon
        '0CCE9221-69AE-11D9-BED3-505054503030' = 'ObjectAccess_AuditCertificationServices'   # Certification Services
        '0CCE9224-69AE-11D9-BED3-505054503030' = 'ObjectAccess_AuditFileShare'   # File Share
        '0CCE9226-69AE-11D9-BED3-505054503030' = 'ObjectAccess_AuditFilteringPlatformConnection'   # Filtering Platform Connection
        '0CCE9227-69AE-11D9-BED3-505054503030' = 'ObjectAccess_AuditOtherObjectAccessEvents'   # Other Object Access Events
        '0CCE9245-69AE-11D9-BED3-505054503030' = 'ObjectAccess_AuditRemovableStorage'   # Removable Storage
        '0CCE9220-69AE-11D9-BED3-505054503030' = 'ObjectAccess_AuditSAM'   # SAM
        '0CCE922F-69AE-11D9-BED3-505054503030' = 'PolicyChange_AuditPolicyChange'   # Audit Policy Change
        '0CCE9230-69AE-11D9-BED3-505054503030' = 'PolicyChange_AuditAuthenticationPolicyChange'   # Authentication Policy Change
        '0CCE9234-69AE-11D9-BED3-505054503030' = 'PolicyChange_AuditOtherPolicyChangeEvents'   # Other Policy Change Events
        '0CCE9228-69AE-11D9-BED3-505054503030' = 'PrivilegeUse_AuditSensitivePrivilegeUse'   # Sensitive Privilege Use
        '0CCE9213-69AE-11D9-BED3-505054503030' = 'System_AuditIPsecDriver'   # IPsec Driver
        '0CCE9210-69AE-11D9-BED3-505054503030' = 'System_AuditSecurityStateChange'   # Security State Change
        '0CCE9211-69AE-11D9-BED3-505054503030' = 'System_AuditSecuritySystemExtension'   # Security System Extension
        '0CCE9212-69AE-11D9-BED3-505054503030' = 'System_AuditSystemIntegrity'   # System Integrity
        '0CCE9214-69AE-11D9-BED3-505054503030' = 'System_AuditOtherSystemEvents'   # Other System Events

    }

    # Registry item Id -> CSP. Value is what to set, in the catalog's terms.
    Registry = @{
        CmdLineAudit     = @{ Csp = 'ADMX_AuditSettings/IncludeCmdLine'; Value = 'Enabled'; Doc = 'policy-csp-admx-auditsettings' }
        ScriptBlock64    = @{ Csp = 'WindowsPowerShell/TurnOnPowerShellScriptBlockLogging'; Value = 'Enabled'; Doc = 'policy-csp-windowspowershell' }
        ModuleLogging64  = @{ Csp = 'ADMX_PowerShellExecutionPolicy/EnableModuleLogging'; Value = 'Enabled'; Doc = 'policy-csp-admx-powershellexecutionpolicy' }
        ModuleNames64    = @{ Csp = 'ADMX_PowerShellExecutionPolicy/EnableModuleLogging'; Value = 'Module names: *'; Doc = 'policy-csp-admx-powershellexecutionpolicy' }
        NtlmInboundAudit = @{ Csp = 'LocalPoliciesSecurityOptions/NetworkSecurity_RestrictNTLM_AuditIncomingNTLMTraffic'; Value = '2 (enable auditing for all accounts)'; Doc = 'policy-csp-localpoliciessecurityoptions' }
    }

    # Channel -> maximum size CSP (policy-csp-eventlogservice). Value is the
    # kit target in KB, the unit the policy takes.
    Channels = @{
        'Application' = 'EventLogService/SpecifyMaximumFileSizeApplicationLog'
        'Security'    = 'EventLogService/SpecifyMaximumFileSizeSecurityLog'
        'System'      = 'EventLogService/SpecifyMaximumFileSizeSystemLog'
    }

    # Registry items with no usable CSP, and why. Channels without a size
    # CSP, SMB auditing and AD CS are explained by the generator.
    NoCsp = @{
        ScriptBlock32      = 'The 32-bit (WOW64) copy of the script block policy has no CSP of its own.'
        ModuleLogging32    = 'The 32-bit (WOW64) copy of the module logging policy has no CSP of its own.'
        ModuleNames32      = 'The 32-bit (WOW64) copy of the module list has no CSP of its own.'
        PS7ScriptBlock64   = 'No built-in CSP for PowerShell 7 policy. Importing its ADMX as a custom template may be blocked by the registry locations Intune allows for imported ADMX.'
        PS7ScriptBlock32   = 'No built-in CSP for PowerShell 7 policy (32-bit copy).'
        PS7ModuleLogging64 = 'No built-in CSP for PowerShell 7 policy. Importing its ADMX as a custom template may be blocked by the registry locations Intune allows for imported ADMX.'
        PS7ModuleLogging32 = 'No built-in CSP for PowerShell 7 policy (32-bit copy).'
        NtlmOutboundAudit  = 'A CSP exists (LocalPoliciesSecurityOptions/NetworkSecurity_RestrictNTLM_OutgoingNTLMTrafficToRemoteServers), but Microsoft lists its value 1 as "Deny all domain accounts", not the registry''s "Audit all". Setting 1 through the CSP could block NTLM, so leave this to the remediation pack.'
        NtlmDomainAudit    = 'No CSP. Domain controllers only; set it by GPO on the DCs.'
    }
}