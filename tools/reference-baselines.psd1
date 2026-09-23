# Published reference baselines, as selections of the kit's settings table.
# Faithful to the scripts in Yamato Security's EventLog-Baseline-Guide
# (bat/ASD.bat, bat/Microsoft_Client.bat, bat/Microsoft_Server.bat,
# extracted 2026-08-31).
#
# AuditPrefixes are the first GUID segment of each enabled audit
# subcategory; RegistryIds and Channels are settings-table Ids/names.
# SMB audit and AD CS items are not addressed by any of these baselines.
#
# Used by tools\New-PresetBaselines.ps1 (ships ASD as presets\ASD.csv) and
# tools\Export-ReferenceTable.ps1 (the Refs column: A / C / S).
@{
    ASD = @{
        AuditPrefixes = @('0CCE9236','0CCE923A','0CCE9237','0CCE9235','0CCE922B','0CCE9217','0CCE9216','0CCE9215','0CCE921C','0CCE921B','0CCE9224','0CCE9227','0CCE922F','0CCE9234','0CCE9212')
        RegistryIds   = @('CmdLineAudit','ScriptBlock64','ScriptBlock32','ModuleLogging64','ModuleLogging32','ModuleNames64','ModuleNames32')
        Channels      = @('Security','System','Application')
    }
    Microsoft_Client = @{
        AuditPrefixes = @('0CCE923F','0CCE9236','0CCE923A','0CCE9237','0CCE9235','0CCE922B','0CCE9216','0CCE9215','0CCE921B','0CCE922F','0CCE9213','0CCE9210','0CCE9211','0CCE9212')
        RegistryIds   = @('CmdLineAudit')
        Channels      = @()
    }
    Microsoft_Server = @{
        AuditPrefixes = @('0CCE923F','0CCE9236','0CCE923A','0CCE9237','0CCE9235','0CCE922B','0CCE923B','0CCE923C','0CCE9216','0CCE9215','0CCE921B','0CCE922F','0CCE9213','0CCE9210','0CCE9211','0CCE9212')
        RegistryIds   = @('CmdLineAudit')
        Channels      = @()
    }
}
