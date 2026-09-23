<#
.SYNOPSIS
    WinLogKit self-checks as a Pester 5 suite. Run them with
    tests\Invoke-KitChecks.ps1 (or Invoke-Pester tests\Kit.Tests.ps1).

.DESCRIPTION
    Safe on any machine: nothing is applied to the host and no admin is
    needed. Generated artefacts go to a temporary folder that is removed
    afterwards. CI runs the suite on Windows PowerShell 5.1 and PowerShell 7.
    Pester is a development and CI dependency only; the kit's own scripts
    still need no modules.
#>

BeforeDiscovery {
    $kitRoot = Split-Path $PSScriptRoot -Parent
    $kitRootFull = (Resolve-Path $kitRoot).Path.TrimEnd('\')
    # Exclusions apply to the path relative to the kit root, so a kit that
    # itself lives under e.g. C:\staging\WELA-2.1.0\kit is not skipped whole.
    # WELA[^\\]* skips unzipped third-party WELA folders.
    $ScriptFiles = @(Get-ChildItem $kitRoot -Filter *.ps1 -Recurse |
        Where-Object { $_.FullName.Substring($kitRootFull.Length) -notmatch '\\(WELA[^\\]*|Baseline|Logs|Results|Evidence|Intune)\\' } |
        ForEach-Object { @{ Name = $_.FullName.Substring($kitRootFull.Length).TrimStart('\'); Path = $_.FullName } })
    $PresetNames = @('Workstation', 'MemberServer', 'DomainController', 'ASD') | ForEach-Object { @{ Name = $_ } }
    $PackFiles = @('Detect-LoggingBaseline.ps1', 'Remediate-LoggingBaseline.ps1') | ForEach-Object { @{ Name = $_ } }
    # The release zip ships tests\ but not docs\: the Reference page check
    # is skipped there rather than failed.
    $HasDocs = Test-Path (Join-Path $kitRoot 'docs')
}

BeforeAll {
    $KitRoot = Split-Path $PSScriptRoot -Parent
    $KitRootFull = (Resolve-Path $KitRoot).Path.TrimEnd('\')
    $ScriptPaths = @(Get-ChildItem $KitRoot -Filter *.ps1 -Recurse |
        Where-Object { $_.FullName.Substring($KitRootFull.Length) -notmatch '\\(WELA[^\\]*|Baseline|Logs|Results|Evidence|Intune)\\' })
    . (Join-Path $KitRoot 'WinLogKit.Settings.ps1')
    . (Join-Path $KitRoot 'WinLogKit.Common.ps1')
    $Engine = (Get-Process -Id $PID).Path
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) "winlogkit-checks-$PID"
    New-Item -ItemType Directory -Path $Tmp -Force | Out-Null

    # Builder output shared by several checks: the recommended (Core) set and
    # everything selected.
    $Csv1 = Join-Path $Tmp 'recommended.csv'
    $Csv2 = Join-Path $Tmp 'all-tiers.csv'
    & (Join-Path $KitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -OutFile $Csv1 -Force | Out-Null
    & (Join-Path $KitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -IncludeHighVolume -OutFile $Csv2 -Force | Out-Null
    $R1 = @(Import-Csv $Csv1)
    $R2 = @(Import-Csv $Csv2)
    $CoreCount = @($R1 | Where-Object { $_.Tier -eq 'Core' }).Count

    # Runs a kit script in a child process of this engine and returns its
    # output and exit code. Stops a script's exit codes ending the run, and
    # relaxes ErrorActionPreference because Windows PowerShell 5.1 turns
    # redirected native stderr into a terminating error under 'Stop'.
    function Invoke-KitChild {
        param([string]$Script, [string[]]$Arguments)
        $prev = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $out = & $Engine -NoProfile -ExecutionPolicy Bypass -File (Join-Path $KitRoot $Script) @Arguments 2>&1 | Out-String
            return @{ Output = $out; Exit = $LASTEXITCODE }
        } finally { $ErrorActionPreference = $prev }
    }
}

AfterAll {
    Remove-Item $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}

Describe 'Scripts' {
    It 'parses <Name>' -ForEach $ScriptFiles {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0 -Because "$Name should parse: $(@($errors | ForEach-Object { "$($_.Message) (line $($_.Extent.StartLineNumber))" }) -join '; ')"
    }

    It 'finds scripts to check (the exclusion filter is not over-matching)' {
        $ScriptPaths.Count | Should -BeGreaterThan 0
    }

    # WELA issue #243: New-Item -Force on an existing registry key wipes its
    # other values (it broke Netlogon on DCs). The kit writes registry only
    # through [Microsoft.Win32.Registry]::SetValue, so every New-Item must
    # declare -ItemType Directory or File.
    It 'declares -ItemType Directory/File on every New-Item (WELA issue #243 class)' {
        $bad = @(foreach ($f in $ScriptPaths) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-Item' }, $true)) {
                $elems = @($c.CommandElements | ForEach-Object { $_.Extent.Text })
                $i = [array]::IndexOf($elems, '-ItemType')
                if (-not ($i -ge 0 -and $i + 1 -lt $elems.Count -and $elems[$i + 1] -match '^(Directory|File)$')) { "$($f.Name):$($c.Extent.StartLineNumber)" }
            }
        })
        $bad | Should -BeNullOrEmpty -Because 'a New-Item without -ItemType could create a registry key and wipe sibling values'
    }

    Context 'helper functions' {
        BeforeAll {
            # Function name -> files that define it. The Intune pack generator
            # embeds its helpers in a here-string, which the AST does not see as
            # definitions: the generated pack must stay self-contained.
            $Defs = @{}
            foreach ($f in $ScriptPaths) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                $rel = $f.FullName.Substring($KitRootFull.Length).TrimStart([char]92)
                foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                    if (-not $Defs.ContainsKey($fn.Name)) { $Defs[$fn.Name] = @() }
                    $Defs[$fn.Name] += $rel
                }
            }
        }

        It 'defines every function exactly once' {
            $dupes = @($Defs.Keys | Where-Object { $Defs[$_].Count -gt 1 } | Sort-Object | ForEach-Object { "$_ ($($Defs[$_] -join ', '))" })
            $dupes | Should -BeNullOrEmpty -Because 'shared helpers belong in WinLogKit.Common.ps1'
        }

        It 'keeps the shared helpers in WinLogKit.Common.ps1 only' {
            $expected = @('Test-IsAdmin', 'Get-DomainRole', 'Test-PowerShell7Installed', 'Get-OsType', 'ConvertTo-NetRegPath', 'Get-RegValue',
                'ConvertFrom-AuditPolicyBackup', 'Get-AuditPolicyByGuid', 'Get-AuditSettingValue', 'Format-AuditSetting', 'Get-SmbAuditState',
                'Get-BaselineItemKeySet', 'Import-BaselineSelection', 'Test-ReferenceBaselineItem', 'Write-IncludeOptionalWarning',
                'Test-TierSelected', 'Resolve-BaselineSelection', 'Test-ItemSelected')
            $notInCommon = @($expected | Where-Object { -not $Defs.ContainsKey($_) -or (($Defs[$_] -join ';') -ne 'WinLogKit.Common.ps1') })
            $notInCommon | Should -BeNullOrEmpty
        }
    }
}

Describe 'Settings table' {
    It 'uses only known behaviour category tags' {
        $bad = @(foreach ($grp in @($BaselineChannels, $BaselineAuditSubcategories, $BaselineRegistrySettings, $BaselineSmbAuditSettings, @($BaselineAdcsAuditFilter))) {
            foreach ($item in $grp) { foreach ($c in $item.Categories) { if ($BaselineCategories -notcontains $c) { "'$c'" } } }
        })
        $bad | Should -BeNullOrEmpty
    }

    It 'has a coverage note for every category' {
        @($BaselineCategories | Where-Object { -not $BaselineCategoryNotes.ContainsKey($_) }) | Should -BeNullOrEmpty
    }

    # v2 has two tiers (ADR-002): anything else would silently never apply.
    It 'puts every item in Core or HighVolume' {
        $bad = @(foreach ($grp in @($BaselineChannels, $BaselineAuditSubcategories, $BaselineRegistrySettings, $BaselineSmbAuditSettings, @($BaselineAdcsAuditFilter))) {
            foreach ($item in $grp) { if (@('Core', 'HighVolume') -notcontains $item.Tier) { "$($item.Tier)" } }
        })
        $bad | Should -BeNullOrEmpty
    }

    It 'has unique, well-formed audit subcategory GUIDs' {
        $guids = @($BaselineAuditSubcategories | ForEach-Object { $_.Guid.ToUpper() })
        @($guids | Sort-Object -Unique).Count | Should -Be $guids.Count -Because 'GUIDs must be unique'
        @($guids | Where-Object { $_ -notmatch '^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$' }) | Should -BeNullOrEmpty
    }
}

Describe 'Baseline builder' {
    It 'writes one row per settings item' {
        $expected = $BaselineChannels.Count + $BaselineAuditSubcategories.Count + $BaselineRegistrySettings.Count + $BaselineSmbAuditSettings.Count + 1
        $R1.Count | Should -Be $expected
    }

    It 'round-trips every lookup key Enable and Test use' {
        $keys = @{}
        foreach ($row in $R1) { $keys[("$($row.ItemType)|$($row.Id)").ToUpper()] = $true }
        $want = @(
            $BaselineChannels | ForEach-Object { "Channel|$($_.Name)" }
            $BaselineAuditSubcategories | ForEach-Object { "AuditPolicy|$($_.Guid)" }
            $BaselineRegistrySettings | ForEach-Object { "Registry|$($_.Id)" }
            $BaselineSmbAuditSettings | ForEach-Object { "SmbAudit|$($_.Id)" }
            "Registry|$($BaselineAdcsAuditFilter.Id)"
        )
        @($want | Where-Object { -not $keys[$_.ToUpper()] }) | Should -BeNullOrEmpty
    }

    It 'selects exactly the Core tier by default' {
        @($R1 | Where-Object { $_.Selected -eq 'Y' -and $_.Tier -eq 'Core' }).Count | Should -Be $CoreCount
        @($R1 | Where-Object { $_.Selected -eq 'Y' -and $_.Tier -ne 'Core' }).Count | Should -Be 0
    }

    It 'selects everything with -IncludeHighVolume' {
        @($R2 | Where-Object { $_.Selected -eq 'Y' }).Count | Should -Be $R2.Count
    }

    # The deprecated v1 switch still parses, only warns, and selects nothing extra.
    It 'warns on -IncludeOptional and changes nothing' {
        $csv3 = Join-Path $Tmp 'include-optional.csv'
        & (Join-Path $KitRoot 'New-LoggingBaseline.ps1') -AcceptRecommended -IncludeOptional -OutFile $csv3 -Force -WarningVariable optWarn -WarningAction SilentlyContinue | Out-Null
        @($optWarn | Where-Object { "$_" -match 'IncludeOptional is deprecated' }).Count | Should -BeGreaterThan 0
        @(Import-Csv $csv3 | Where-Object { $_.Selected -eq 'Y' }).Count | Should -Be $CoreCount
    }

    # A CSV with the right columns but no row matching this kit must be
    # rejected (Test would otherwise report everything NOT APPLICABLE and exit
    # 0); one stale row only warns. Child processes, because the rejection is
    # a terminating error in-session.
    It 'rejects a selection CSV that matches nothing in the kit' {
        $bad = Join-Path $Tmp 'unknown-only.csv'
        '"ItemType","Id","Selected"', '"Channel","No-Such-Channel/Operational","Y"' | Set-Content $bad
        $r = Invoke-KitChild 'New-LoggingBaseline.ps1' @('-Show', '-BaselineFile', $bad)
        $r.Exit | Should -Not -Be 0
        $r.Output | Should -Match 'No row in the baseline file matches'
    }

    It 'warns about one unknown row and carries on' {
        $stale = Join-Path $Tmp 'one-stale-row.csv'
        (Get-Content $Csv1) + '"Channel","No-Such-Channel/Operational","Core","All","Y","Y","","",""' | Set-Content $stale
        $r = Invoke-KitChild 'New-LoggingBaseline.ps1' @('-Show', '-BaselineFile', $stale)
        $r.Exit | Should -Be 0
        $r.Output | Should -Match 'does not know, ignored: CHANNEL\|NO-SUCH-CHANNEL/OPERATIONAL'
    }
}

Describe 'Intune pack' {
    BeforeAll {
        $PackDir = Join-Path $Tmp 'intune'
        & (Join-Path $KitRoot 'fleet\New-IntuneRemediationPack.ps1') -OutDir $PackDir | Out-Null
    }

    It 'generates <Name> that parses with no placeholders left' -ForEach $PackFiles {
        $p = Join-Path $PackDir $Name
        $p | Should -Exist
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errors) | Out-Null
        $errors.Count | Should -Be 0
        (Get-Content $p -Raw) | Should -Not -Match '__(MODE|ITEMS|COUNT|SOURCE|FILENAME)__'
    }

    # The recommended CSV selects only Core, so no HighVolume item may be embedded.
    It 'honours the baseline CSV selection' {
        $packDir2 = Join-Path $Tmp 'intune-csv'
        & (Join-Path $KitRoot 'fleet\New-IntuneRemediationPack.ps1') -OutDir $packDir2 -BaselineFile $Csv1 | Out-Null
        (Get-Content (Join-Path $packDir2 'Detect-LoggingBaseline.ps1') -Raw) | Should -Not -Match 'EnableModuleLogging'
    }
}

Describe 'Presets' {
    BeforeAll {
        $PresetTmp = Join-Path $Tmp 'presets'
        & (Join-Path $KitRoot 'tools\New-PresetBaselines.ps1') -OutDir $PresetTmp | Out-Null
        # Compare every column, so descriptive fields (Purpose, Risk, Tier...)
        # in committed presets cannot go stale while the check passes.
        $RowKey = { ($_.PSObject.Properties | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '|' }
    }

    # ADR-002: exactly these four ship; a stray CSV would be an unmaintained
    # baseline users might pick.
    It 'ships exactly the four generated presets' {
        $names = @('Workstation', 'MemberServer', 'DomainController', 'ASD')
        @(Get-ChildItem (Join-Path $KitRoot 'presets') -Filter *.csv | Where-Object { $names -notcontains $_.BaseName } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
    }

    It 'keeps <Name>.csv in step with the generator' -ForEach $PresetNames {
        $committed = Join-Path $KitRoot "presets\$Name.csv"
        $committed | Should -Exist -Because 'run tools\New-PresetBaselines.ps1'
        $a = @(Import-Csv $committed | ForEach-Object $RowKey | Sort-Object)
        $b = @(Import-Csv (Join-Path $PresetTmp "$Name.csv") | ForEach-Object $RowKey | Sort-Object)
        Compare-Object $a $b | Should -BeNullOrEmpty -Because "presets\$Name.csv drifted - rerun tools\New-PresetBaselines.ps1 under Windows PowerShell 5.1"
    }
}

Describe 'Reference page' {
    It 'matches the generator' -Skip:(-not $HasDocs) {
        $refTmp = Join-Path $Tmp 'reference.md'
        & (Join-Path $KitRoot 'tools\Export-ReferenceTable.ps1') -OutFile $refTmp | Out-Null
        $committed = Join-Path $KitRoot 'docs\reference.md'
        $committed | Should -Exist
        # Line-ending neutral: git may check the page out with CRLF.
        ((Get-Content $committed -Raw) -replace "`r`n", "`n") | Should -BeExactly ((Get-Content $refTmp -Raw) -replace "`r`n", "`n") -Because 'rerun tools\Export-ReferenceTable.ps1'
    }
}

# #47 / #48: the Settings catalog and Group Policy pages. Every kit item has
# a CSP or a reason it has none, and a Group Policy path or a reason; the
# map names nothing the kit doesn't have.
Describe 'Policy pages' {
    BeforeAll {
        $PolicyMap = Import-PowerShellDataFile (Join-Path $KitRoot 'tools\policy-map.psd1')
    }

    It 'match the generator' -Skip:(-not $HasDocs) {
        $polTmp = Join-Path $Tmp 'policy-pages'
        & (Join-Path $KitRoot 'tools\Export-PolicyTables.ps1') -OutDir $polTmp | Out-Null
        foreach ($page in 'intune-csp.md', 'gpo-paths.md') {
            $committed = Join-Path $KitRoot "docs\$page"
            $committed | Should -Exist
            # Line-ending neutral: git may check the page out with CRLF.
            ((Get-Content $committed -Raw) -replace "`r`n", "`n") | Should -BeExactly ((Get-Content (Join-Path $polTmp $page) -Raw) -replace "`r`n", "`n") -Because "rerun tools\Export-PolicyTables.ps1 ($page)"
        }
    }

    It 'cover every audit subcategory, registry item and SMB audit item' {
        $auditKeys = @($PolicyMap.Audit.Keys | ForEach-Object { $_.ToUpper() })
        @($BaselineAuditSubcategories | Where-Object { $auditKeys -notcontains $_.Guid.ToUpper() } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
        @($BaselineSmbAuditSettings | Where-Object { -not $PolicyMap.Smb.ContainsKey($_.Id) } | ForEach-Object { $_.Id }) | Should -BeNullOrEmpty
        # Each registry item: exactly one of Csp / NoCsp, and of Gp / NoGp.
        @($BaselineRegistrySettings | Where-Object {
            $m = $PolicyMap.Registry[$_.Id]
            ($null -eq $m) -or -not ($m.ContainsKey('Csp') -xor $m.ContainsKey('NoCsp')) -or -not ($m.ContainsKey('Gp') -xor $m.ContainsKey('NoGp'))
        } | ForEach-Object { $_.Id }) | Should -BeNullOrEmpty
    }

    It 'name only items the kit has, and only known audit categories' {
        $guids = @($BaselineAuditSubcategories | ForEach-Object { $_.Guid.ToUpper() })
        @($PolicyMap.Audit.Keys | Where-Object { $guids -notcontains $_.ToUpper() }) | Should -BeNullOrEmpty
        @($PolicyMap.Registry.Keys | Where-Object { @($BaselineRegistrySettings | ForEach-Object { $_.Id }) -notcontains $_ }) | Should -BeNullOrEmpty
        @($PolicyMap.Smb.Keys | Where-Object { @($BaselineSmbAuditSettings | ForEach-Object { $_.Id }) -notcontains $_ }) | Should -BeNullOrEmpty
        @($PolicyMap.Channels.Keys | Where-Object { @($BaselineChannels | ForEach-Object { $_.Name }) -notcontains $_ }) | Should -BeNullOrEmpty
        @($PolicyMap.Audit.Values | Where-Object { -not $PolicyMap.AuditCategories.ContainsKey(($_.Csp -split '_')[0]) } | ForEach-Object { $_.Csp }) | Should -BeNullOrEmpty
    }
}
Describe 'GPO pack' {
    BeforeAll {
        $GpoTmp = Join-Path $Tmp 'gpo'
        & (Join-Path $KitRoot 'fleet\New-GpoPack.ps1') -OutDir $GpoTmp -IncludeHighVolume | Out-Null
    }

    It 'writes one audit.csv row per selected subcategory' {
        $expected = @($BaselineAuditSubcategories | Where-Object { $_.Tier -eq 'Core' -or $_.Tier -eq 'HighVolume' }).Count
        @(Import-Csv (Join-Path $GpoTmp 'audit.csv')).Count | Should -Be $expected
    }

    It 'puts the policy registry values in registry.txt' {
        $reg = Get-Content (Join-Path $GpoTmp 'registry.txt') -Raw
        $reg | Should -Match 'EnableScriptBlockLogging'
        # SMB auditing goes through its Lanman Server / Workstation policies (#48).
        $reg | Should -Match 'Microsoft\\Windows\\LanmanServer\r?\nAuditClientDoesNotSupportEncryption\r?\nDWORD:1'
        $reg | Should -Match 'Microsoft\\Windows\\LanmanWorkstation\r?\nAuditServerDoesNotSupportSigning\r?\nDWORD:1'
    }
}

Describe 'ATT&CK coverage' {
    It 'maps only settings-table items in event_map.csv' {
        $bad = @(foreach ($m in (Import-Csv (Join-Path $KitRoot 'data\attack\event_map.csv'))) {
            if ($m.item_type -eq 'AuditPolicy' -and $m.item_id -ne '' -and -not @($BaselineAuditSubcategories | Where-Object { $_.Guid.ToUpper() -eq $m.item_id.ToUpper() }).Count) { "GUID $($m.item_id)" }
            if ($m.item_type -eq 'Channel' -and $m.item_id -ne '' -and -not @($BaselineChannels | Where-Object { $_.Name -eq $m.item_id }).Count) { "channel $($m.item_id)" }
        })
        $bad | Should -BeNullOrEmpty
    }

    # Core-tier sanity: about 1480 analytic rows, about 199 observable at
    # Core (measured at snapshot time); Sysmon-only rows dominate the rest.
    It 'joins the native mapping for the Core tier' {
        $covTmp = Join-Path $Tmp 'cov'
        & (Join-Path $KitRoot 'tools\Export-AttackCoverage.ps1') -OutDir $covTmp | Out-Null
        $detail = Get-ChildItem $covTmp -Filter 'AttackCoverage_Detail_*.csv' | Select-Object -First 1
        $detail | Should -Not -BeNullOrEmpty
        $rows = @(Import-Csv $detail.FullName)
        $rows.Count | Should -BeGreaterThan 1400
        @($rows | Where-Object { $_.Status -eq 'Observable' }).Count | Should -BeGreaterOrEqual 150
    }
}

Describe 'WEF subscription' {
    BeforeAll {
        $WefTmp = Join-Path $Tmp 'wef'
        & (Join-Path $KitRoot 'fleet\New-WefSubscription.ps1') -OutDir $WefTmp -BaselineFile (Join-Path $KitRoot 'presets\ASD.csv') -SubscriptionId 'CheckSub' | Out-Null
        [xml]$Wx = Get-Content (Join-Path $WefTmp 'CheckSub.xml') -Raw
    }

    It 'writes valid XML with one query per selected channel (3 for ASD)' {
        [regex]::Matches($Wx.Subscription.Query.'#cdata-section', '<Query ').Count | Should -Be 3
    }

    # v2 (ADR-002): every Select is "*" and there is no Suppress.
    It 'forwards whole channels' {
        [xml]$ql = $Wx.Subscription.Query.InnerText
        $selects = @($ql.QueryList.Query | ForEach-Object { @($_.Select) } | ForEach-Object { $_.'#text' })
        $selects.Count | Should -Be 3
        @($selects | Where-Object { $_ -ne '*' }) | Should -BeNullOrEmpty
        @($ql.QueryList.Query | Where-Object { $_.SelectNodes('Suppress').Count -gt 0 }).Count | Should -Be 0
    }

    It 'stops the removed -Filter Baseline with a migration message' {
        $r = Invoke-KitChild 'fleet\New-WefSubscription.ps1' @('-OutDir', (Join-Path $Tmp 'wefOld'), '-Filter', 'Baseline')
        $r.Exit | Should -Not -Be 0
        $r.Output | Should -Match 'removed in v2'
    }
}

# #44: the rollback baseline picks up settings a later kit version adds.
# Enable needs admin, so its two state functions are lifted out by AST and
# run against a first-run JSON that lacks the PowerShell 7 items.
Describe 'Rollback baseline' {
    BeforeAll {
        $enableAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $KitRoot 'Enable-LoggingBaseline.ps1'), [ref]$null, [ref]$null)
        $StateFns = @($enableAst.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] -and @('Get-CurrentKitState', 'Add-NewItemsToFirstRun') -contains $a.Name }, $true))
        foreach ($fn in $StateFns) { . ([scriptblock]::Create($fn.Extent.Text)) }
        . ([scriptblock]::Create('function Get-AdcsRegPath { $null }'))
        $AllState = Get-CurrentKitState
        $FirstJson = Join-Path $Tmp 'first-run.json'
        @{ CapturedUtc = '2026-01-01T00:00:00'; Host = 'check'; Channels = $AllState.Channels
           Registry = @($AllState.Registry | Where-Object { $_.Name -ne 'UseWindowsPowerShellPolicySetting' }); SmbAudit = $AllState.SmbAudit } |
            ConvertTo-Json -Depth 5 | Set-Content -Path $FirstJson -Encoding UTF8
        $Added1 = Add-NewItemsToFirstRun -Path $FirstJson
        $Added2 = Add-NewItemsToFirstRun -Path $FirstJson
        $After = Get-Content $FirstJson -Raw | ConvertFrom-Json
    }

    It 'finds both state functions in Enable' {
        $StateFns.Count | Should -Be 2
    }

    It 'adds the 4 PowerShell 7 items once, then nothing' {
        $Added1 | Should -Be 4
        $Added2 | Should -Be 0
        @($After.Registry | Where-Object { $_.Name -eq 'UseWindowsPowerShellPolicySetting' -and $_.PSObject.Properties.Name -contains 'Existed' -and $_.AddedUtc }).Count | Should -Be 4
        @($After.Registry).Count | Should -Be @($AllState.Registry).Count
    }

    It 'swaps the file in with a .bak kept and no .tmp left' {
        "$FirstJson.bak" | Should -Exist
        "$FirstJson.tmp" | Should -Not -Exist
    }
}

# #44: PowerShell 7 follows the Windows PowerShell policy.
Describe 'PowerShell 7 items' {
    BeforeAll {
        $Pairs = @{ PS7ScriptBlock64 = 'ScriptBlock64'; PS7ScriptBlock32 = 'ScriptBlock32'; PS7ModuleLogging64 = 'ModuleLogging64'; PS7ModuleLogging32 = 'ModuleLogging32' }
    }

    It 'sit on the PowerShellCore twin of their Windows PowerShell keys' {
        $bad = @(foreach ($k in $Pairs.Keys) {
            $ps7 = @($BaselineRegistrySettings | Where-Object { $_.Id -eq $k })
            $win = @($BaselineRegistrySettings | Where-Object { $_.Id -eq $Pairs[$k] })
            if ($ps7.Count -ne 1 -or $win.Count -ne 1) { "$k or $($Pairs[$k]) missing"; continue }
            if ($ps7[0].Path -ne ($win[0].Path -replace '\\Windows\\PowerShell\\', '\PowerShellCore\')) { "$k is not on the PowerShellCore twin of $($Pairs[$k])" }
        })
        $bad | Should -BeNullOrEmpty
    }

    It 'are selected in every role preset that selects their Windows PowerShell policy' {
        $bad = @(foreach ($name in @('Workstation', 'MemberServer', 'DomainController')) {
            $on = @{}; Import-Csv (Join-Path $KitRoot "presets\$name.csv") | Where-Object { $_.Selected -eq 'Y' } | ForEach-Object { $on[$_.Id] = $true }
            foreach ($k in $Pairs.Keys) { if ($on.ContainsKey($Pairs[$k]) -and -not $on.ContainsKey($k)) { "$name selects $($Pairs[$k]) without $k" } }
        })
        $bad | Should -BeNullOrEmpty
    }
}

# #45: audit policy is read as numbers, not words. The same policy exported
# on English and on German Windows (header row and setting text translated,
# values identical) must parse to the same map.
Describe 'Audit policy reading' {
    BeforeAll {
        $Fx = Join-Path (Join-Path $KitRoot 'tests') 'fixtures'
        $EnLines = @(Get-Content (Join-Path $Fx 'auditpol-backup-en.csv') -Encoding UTF8)
        $MapEn = ConvertFrom-AuditPolicyBackup -Lines $EnLines
        $MapDe = ConvertFrom-AuditPolicyBackup -Lines (Get-Content (Join-Path $Fx 'auditpol-backup-de.csv') -Encoding UTF8)
    }

    It 'parses English and German exports identically' {
        $MapEn.Count | Should -BeGreaterOrEqual 50
        $MapDe.Count | Should -Be $MapEn.Count
        @($MapEn.Keys | Where-Object { -not $MapDe.ContainsKey($_) -or $MapDe[$_] -ne $MapEn[$_] }) | Should -BeNullOrEmpty
    }

    It 'covers every kit subcategory and skips the Option: rows' {
        @($BaselineAuditSubcategories | Where-Object { -not $MapEn.ContainsKey($_.Guid.ToUpper()) } | ForEach-Object { $_.Name }) | Should -BeNullOrEmpty
        @($MapEn.Keys | Where-Object { $_ -notmatch '^[0-9A-F]{8}(-[0-9A-F]{4}){3}-[0-9A-F]{12}$' }) | Should -BeNullOrEmpty
    }

    It 'prefers system rows over a per-user row placed ahead of them' {
        $logon = '0CCE9215-69AE-11D9-BED3-505054503030'
        $map = ConvertFrom-AuditPolicyBackup -Lines (@($EnLines[0], "HOST01,User,Logon,{$logon},No Auditing,,0") + @($EnLines | Select-Object -Skip 1))
        $MapEn[$logon] | Should -Not -Be 0
        $map[$logon] | Should -Be $MapEn[$logon]
    }

    It 'leaves no script matching on the translated text' {
        @(foreach ($rel in @('WinLogKit.Common.ps1', 'Enable-LoggingBaseline.ps1', 'Test-LoggingBaseline.ps1', 'fleet\New-IntuneRemediationPack.ps1')) {
            if (Select-String -Path (Join-Path $KitRoot $rel) -Pattern "'Inclusion Setting'|match 'Success'|match 'Failure'|auditpol /get /category" -Quiet) { $rel }
        }) | Should -BeNullOrEmpty
    }

    It 'converts between flags, values and English text' {
        Get-AuditSettingValue $true $false | Should -Be 1
        Get-AuditSettingValue $true $true | Should -Be 3
        Format-AuditSetting 3 | Should -Be 'Success and Failure'
        Format-AuditSetting $null | Should -Be 'Unknown'
    }
}

# #51: will the selected logs fit on their drive once full? Sizes only ever
# go up, a log's own file already counts, and it is per drive.
Describe 'Log storage check' {
    BeforeAll {
        function New-Log([string]$Path, $FileSize, [double]$Current, [double]$Target) {
            [pscustomobject]@{ LogFilePath = $Path; FileSize = $FileSize; MaximumSizeInBytes = $Current; TargetBytes = $Target }
        }
        $Logs = @(
            (New-Log '%SystemRoot%\System32\Winevt\Logs\Security.evtx' 20MB 20MB 1GB),
            (New-Log 'C:\Windows\System32\Winevt\Logs\System.evtx' $null 128MB 64MB),
            (New-Log 'D:\Logs\Sysmon.evtx' 512MB 1GB 1GB)
        )
    }

    It 'adds up growth and raised sizes per drive' {
        $c = @(Get-LogStorageCheck -Logs $Logs -DriveSpace @{ 'C:\' = @{ Free = 100GB; Total = 200GB }; 'D:\' = @{ Free = 100GB; Total = 200GB } })
        $c.Count | Should -Be 2
        $cDrive = $c | Where-Object { $_.Drive -eq 'C:\' }
        $cDrive.Logs | Should -Be 2
        $cDrive.RaiseGB | Should -Be ([math]::Round((1GB - 20MB) / 1GB, 1))
        $cDrive.GrowthGB | Should -Be ([math]::Round((1GB - 20MB + 128MB) / 1GB, 1))
        ($c | Where-Object { $_.Drive -eq 'D:\' }).GrowthGB | Should -Be 0.5
        @($c | Where-Object { $_.Status -ne 'OK' }) | Should -BeNullOrEmpty
    }

    It 'flags Low under the free-space threshold and Insufficient when the logs cannot fit' {
        (Get-LogStorageCheck -Logs $Logs[0] -DriveSpace @{ 'C:\' = @{ Free = 10GB; Total = 200GB } }).Status | Should -Be 'Low'
        (Get-LogStorageCheck -Logs $Logs[0] -DriveSpace @{ 'C:\' = @{ Free = 500MB; Total = 200GB } }).Status | Should -Be 'Insufficient'
    }

    It 'is wired into Enable and Test' {
        foreach ($rel in 'Enable-LoggingBaseline.ps1', 'Test-LoggingBaseline.ps1') {
            Select-String -Path (Join-Path $KitRoot $rel) -Pattern 'Write-LogStorageCheck' -Quiet | Should -BeTrue -Because $rel
        }
    }
}
