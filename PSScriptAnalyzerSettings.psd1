@{
    # PSScriptAnalyzer configuration for WinLogKit (used by CI and local runs:
    #   Invoke-ScriptAnalyzer -Path . -Settings .\PSScriptAnalyzerSettings.psd1 -Recurse)
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # The kit is an interactive console tool: Write-Host with colour IS the UI.
        'PSAvoidUsingWriteHost'

        # LoggingBaseline.Settings.ps1 defines script-scope tables consumed by the
        # other scripts after dot-sourcing; per-file analysis cannot see that.
        'PSUseDeclaredVarsMoreThanAssignments'

        # Internal helpers (Set-RegValue, Set-SmbAuditSetting) are only invoked
        # inside their callers' $PSCmdlet.ShouldProcess gates; adding a second
        # ShouldProcess layer would double-prompt under -Confirm.
        'PSUseShouldProcessForStateChangingFunctions'
    )
}
