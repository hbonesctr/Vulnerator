# End-to-end test of Vulnerator's checklist import (CKL and CKLB) against a scratch database.
# Loads the built Vulnerator.exe, creates a fresh database with the app's own DatabaseBuilder,
# imports the synthetic fixtures with the real readers, and checks the results with SQL.
#
# Runs on Windows PowerShell 5.1 (.NET Framework 4.8). Pure ASCII; no PowerShell 7 syntax.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools\tests\Test-ChecklistImport.ps1 -BinDir bin\Release
param(
    [Parameter(Mandatory = $true)][string]$BinDir,
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$binPath = (Resolve-Path $BinDir).Path
if ($OutDir -ne '') { $OutDir = [System.IO.Path]::GetFullPath((Join-Path (Get-Location).Path $OutDir)) }
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorTest_' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($workDir)
$dbPath = Join-Path $workDir 'test.sqlite'

$script:failures = New-Object System.Collections.Generic.List[string]
function Assert-That {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { Write-Host ('PASS ' + $Message) }
    else {
        Write-Host ('FAIL ' + $Message)
        Write-Annotation 'error' ('FAIL ' + $Message)
        $script:failures.Add($Message)
    }
}

function Write-Annotation {
    # GitHub Actions annotation (visible on the run page and through the checks API).
    param([string]$Level, [string]$Text)
    if ($env:GITHUB_ACTIONS -ne 'true') { return }
    $clean = $Text.Replace('%', '%25').Replace("`r", '').Replace("`n", '%0A')
    if ($clean.Length -gt 3000) { $clean = $clean.Substring(0, 3000) }
    Write-Host ('::' + $Level + '::' + $clean)
}

function Invoke-Sql {
    param([string]$Sql, [hashtable]$Parameters = @{})
    $connection = New-Object System.Data.SQLite.SQLiteConnection ('Data Source=' + $dbPath + ';Version=3;datetimeformat=Ticks;')
    $connection.Open()
    try {
        $command = $connection.CreateCommand()
        $command.CommandText = $Sql
        foreach ($key in $Parameters.Keys) { [void]$command.Parameters.AddWithValue($key, $Parameters[$key]) }
        $table = New-Object System.Data.DataTable
        $reader = $command.ExecuteReader()
        try { $table.Load($reader) } finally { $reader.Dispose() }
        return , $table
    }
    finally { $connection.Dispose() }
}

function Get-Scalar {
    param([string]$Sql, [hashtable]$Parameters = @{})
    $t = Invoke-Sql $Sql $Parameters
    if ($t.Rows.Count -eq 0) { return $null }
    return $t.Rows[0][0]
}

function Import-Checklist {
    param([string]$Path, [string]$Group)
    $file = New-Object Vulnerator.Model.Object.File ([System.IO.Path]::GetFileNameWithoutExtension($Path), 'Checklist', 'Ready', $Path, 'True')
    if ($Path.EndsWith('.cklb', [StringComparison]::OrdinalIgnoreCase)) {
        return (New-Object Vulnerator.Model.BusinessLogic.CklbReader).ReadCklbFile($file, $Group)
    }
    return (New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($file, $Group)
}

function Get-Counts {
    return @{
        UniqueFindings  = [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings')
        Vulnerabilities = [int](Get-Scalar 'SELECT COUNT(*) FROM Vulnerabilities')
    }
}

$statusSql = 'SELECT UF.Status FROM UniqueFindings UF JOIN Hardware H ON UF.Hardware_ID = H.Hardware_ID ' +
    'JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID ' +
    'WHERE H.DiscoveredHostName = @h AND V.UniqueVulnerabilityIdentifier = @v'

try {
    # --- Load the application and point it at a scratch database ----------------------------
    Add-Type -AssemblyName System.Configuration
    [System.IO.Directory]::SetCurrentDirectory($binPath)
    $app = [System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'Vulnerator.exe'))
    [void][System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'System.Data.SQLite.dll'))
    $log4net = [System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'log4net.dll'))
    $configure = $log4net.GetType('log4net.Config.BasicConfigurator').GetMethod('Configure', [Type[]]@())
    if ($null -ne $configure) { [void]$configure.Invoke($null, $null) }

    # Properties.Settings is internal: set values through the public ApplicationSettingsBase indexer.
    $settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
    $defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
    $indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
    $indexer.SetValue($defaultSettings, $dbPath, [object[]]@('Database'))
    $indexer.SetValue($defaultSettings, 'ci-test', [object[]]@('ActiveUser'))
    Write-Host ('Scratch database: ' + $dbPath)

    # --- Database creation ---------------------------------------------------------------------
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)
    Assert-That ([System.IO.File]::Exists($dbPath)) 'database file created'
    Assert-That ([int](Get-Scalar 'PRAGMA user_version') -eq 6) 'reference data version is 6 (Rev 5, CCI list 2026-07-14)'
    Assert-That ([int](Get-Scalar "SELECT COUNT(*) FROM Groups WHERE GroupName = 'All'") -eq 1) 'default group "All" seeded'
    Assert-That ([int](Get-Scalar 'SELECT COUNT(*) FROM NIST_ControlsCCIs') -gt 3000) 'Rev 5 CCI-to-control mappings loaded'
    $cciRows = [int](Get-Scalar 'SELECT COUNT(*) FROM CCIs')
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)
    Assert-That ([int](Get-Scalar 'SELECT COUNT(*) FROM CCIs') -eq $cciRows) 'second launch does not duplicate CCIs'

    [void](Invoke-Sql "INSERT INTO Groups (GroupName, GroupTier, IsAccreditation, IsPlatform, FISCAM_Applies, HasForeignNationals) VALUES ('TestGroup', 1, 'False', 'False', 'False', 'False')")

    # --- CKL import ---------------------------------------------------------------------------
    $result = Import-Checklist (Join-Path $fixtures 'multi-stig.ckl') 'TestGroup'
    Assert-That ($result -eq 'Processed') ('multi-STIG CKL imports (got "' + $result + '")')
    $counts = Get-Counts
    Assert-That ($counts['UniqueFindings'] -eq 3) ('3 findings from 2 STIGs in one CKL (got ' + $counts['UniqueFindings'] + ')')

    $groupName = Get-Scalar ("SELECT G.GroupName FROM HardwareGroups HG JOIN Hardware H ON HG.Hardware_ID = H.Hardware_ID " +
        "JOIN Groups G ON HG.Group_ID = G.Group_ID WHERE H.DiscoveredHostName = 'TESTHOST01' AND G.GroupName <> 'All'")
    Assert-That ($groupName -eq 'TestGroup') ('host is filed under the selected group (got "' + $groupName + '")')

    $serverRelease = Get-Scalar "SELECT SourceRelease FROM VulnerabilitySources WHERE SourceName LIKE '%Test Server%'"
    $browserRelease = Get-Scalar "SELECT SourceRelease FROM VulnerabilitySources WHERE SourceName LIKE '%Test Browser%'"
    Assert-That ([string]$serverRelease -eq '5') ('server STIG release is 5 (got "' + $serverRelease + '")')
    Assert-That ([string]$browserRelease -eq '3') ('second STIG keeps its own release 3 (got "' + $browserRelease + '")')

    $datedRows = [int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-1001' AND PublishedDate IS NOT NULL")
    $undatedRows = [int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-2001' AND PublishedDate IS NULL")
    Assert-That ($datedRows -eq 1) 'single-digit benchmark date "4 Jan 2026" is parsed'
    Assert-That ($undatedRows -eq 1) 'STIG without a benchmark date imports with no date'

    $poamSql = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'Resources\DdlFiles\StoredProcedures\Select\EmassPoamVulnerabilities.dml'))
    $poam = Invoke-Sql $poamSql
    $controls = @{}
    foreach ($row in $poam.Rows) { $controls[[string]$row['UniqueVulnerabilityIdentifier']] = [string]$row['NIST_Controls'] }
    Assert-That ($controls['SV-1001'] -eq 'AC-2(1)') ('POA&M shows SV-1001 as AC-2(1) (got "' + $controls['SV-1001'] + '")')
    Assert-That ($controls['SV-1002'] -eq 'CM-6') ('POA&M shows base control CM-6, not blank (got "' + $controls['SV-1002'] + '")')
    Assert-That ($controls['SV-2001'] -eq 'AC-1') ('POA&M shows SV-2001 as AC-1 (got "' + $controls['SV-2001'] + '")')

    $before = Get-Counts
    $result = Import-Checklist (Join-Path $fixtures 'multi-stig.ckl') 'TestGroup'
    $after = Get-Counts
    Assert-That (($result -eq 'Processed') -and ($after['UniqueFindings'] -eq $before['UniqueFindings']) -and ($after['Vulnerabilities'] -eq $before['Vulnerabilities'])) 're-importing the same CKL creates no duplicates'

    $result = Import-Checklist (Join-Path $fixtures 'older-release.ckl') 'TestGroup'
    $remaining = [int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-1002'")
    Assert-That (($result -eq 'Processed') -and ($remaining -ge 1)) 'importing an older-release CKL does not delete library entries'

    $before = Get-Counts
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Import-Checklist (Join-Path $fixtures 'truncated.ckl') 'TestGroup'
    $watch.Stop()
    $after = Get-Counts
    Assert-That ($result.StartsWith('Failed')) ('truncated CKL is reported as failed (got "' + $result + '")')
    Assert-That ($watch.Elapsed.TotalSeconds -lt 30) 'truncated CKL fails fast instead of hanging'
    Assert-That ($after['UniqueFindings'] -eq $before['UniqueFindings']) 'a failed import leaves no partial findings'

    # --- CKLB import --------------------------------------------------------------------------
    $converted = Join-Path $workDir 'viewer3.ckl'
    [Vulnerator.Model.BusinessLogic.CklbReader]::ConvertToCkl((Join-Path $fixtures 'viewer3.cklb'), $converted)
    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($converted)
    Assert-That ($xml.SelectNodes('//VULN').Count -eq 2) 'CKLB converts to a CKL with 2 rules'
    Assert-That ($xml.SelectNodes("//STIG_DATA[VULN_ATTRIBUTE='LEGACY_ID']").Count -eq 2) 'CKLB legacy IDs are carried over'
    $fallbackRule = $xml.SelectSingleNode("//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='V-1002']]/STIG_DATA[VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA").InnerText
    Assert-That ($fallbackRule -eq 'SV-1002r1') ('empty rule_id_src falls back to rule_id (got "' + $fallbackRule + '")')

    $result = Import-Checklist (Join-Path $fixtures 'viewer3.cklb') 'TestGroup'
    Assert-That ($result -eq 'Processed') ('CKLB imports (got "' + $result + '")')
    $cklbFindings = [int](Get-Scalar ("SELECT COUNT(*) FROM UniqueFindings UF JOIN Hardware H ON UF.Hardware_ID = H.Hardware_ID " +
        "WHERE H.DiscoveredHostName = 'TESTHOST02'"))
    Assert-That ($cklbFindings -eq 2) ('CKLB host has 2 findings (got ' + $cklbFindings + ')')

    $cklNaf = Get-Scalar $statusSql @{ '@h' = 'TESTHOST01'; '@v' = 'SV-1002' }
    $cklbNaf = Get-Scalar $statusSql @{ '@h' = 'TESTHOST02'; '@v' = 'SV-1001' }
    $cklOpen = Get-Scalar $statusSql @{ '@h' = 'TESTHOST01'; '@v' = 'SV-1001' }
    $cklbOpen = Get-Scalar $statusSql @{ '@h' = 'TESTHOST02'; '@v' = 'SV-1002' }
    Assert-That (($cklbNaf -eq $cklNaf) -and ($cklbNaf -eq 'Completed')) ('CKLB "not_a_finding" maps like CKL NotAFinding (got "' + $cklbNaf + '")')
    Assert-That (($cklbOpen -eq $cklOpen) -and ($cklbOpen -eq 'Ongoing')) ('CKLB "open" maps like CKL Open (got "' + $cklbOpen + '")')

    $override = Get-Scalar ("SELECT UF.SeverityOverride FROM UniqueFindings UF JOIN Hardware H ON UF.Hardware_ID = H.Hardware_ID " +
        "JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE H.DiscoveredHostName = 'TESTHOST02' AND V.UniqueVulnerabilityIdentifier = 'SV-1002'")
    Assert-That ([string]$override -eq 'low') ('CKLB severity override is kept (got "' + $override + '")')

    $sourceFile = Get-Scalar ("SELECT COUNT(*) FROM UniqueFindingsSourceFiles WHERE FindingSourceFileName LIKE '%viewer3%'")
    Assert-That ([int]$sourceFile -ge 1) 'CKLB findings are attributed to the original .cklb file name'

    # --- eMASS exports ------------------------------------------------------------------------
    $builder = [Vulnerator.Model.BusinessLogic.Reports.EmassPoamBuilder]
    Assert-That ($builder::RawRiskToLevel('I') -eq 'High' -and $builder::RawRiskToLevel('II') -eq 'Moderate' -and $builder::RawRiskToLevel('III') -eq 'Low') 'CAT I/II/III map to High/Moderate/Low'
    Assert-That ($builder::ToSecurityCheck('SV-1001', '2') -eq 'SV-1001r2_rule') 'STIG rule renders as SV-1001r2_rule'
    Assert-That ($builder::ToSecurityCheck('21745', '') -eq '21745') 'Nessus plugin ID is kept as-is'
    Assert-That ($builder::ToEmassStatus('Ongoing', 'Completed') -eq 'Completed') 'a mitigation status overrides the scan status'
    Assert-That ($null -eq $builder::ToEmassStatus('Not Applicable', '')) 'Not Applicable findings stay off the POA&M'
    Assert-That ($builder::ToEmassLevel('medium') -eq 'Moderate') 'medium normalizes to Moderate'

    # Report filters pick up groups created since launch on the next launch; simulate one.
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)
    $indexer.SetValue($defaultSettings, 'Test Org', [object[]]@('Organization'))
    $indexer.SetValue($defaultSettings, 'Pat Tester', [object[]]@('Name'))
    $indexer.SetValue($defaultSettings, '555-0100', [object[]]@('Phone'))
    $indexer.SetValue($defaultSettings, 'pat.tester@example.test', [object[]]@('Email'))
    $indexer.SetValue($defaultSettings, 'Test System', [object[]]@('EmassSystemName'))
    $indexer.SetValue($defaultSettings, 'Sustainment funding', [object[]]@('EmassResourcesRequired'))
    $indexer.SetValue($defaultSettings, '90', [object[]]@('EmassScheduledCompletionDays'))

    if ($OutDir -eq '') { $OutDir = $workDir }
    [void][System.IO.Directory]::CreateDirectory($OutDir)
    $poamPath = Join-Path $OutDir 'sample-eMASS-POAM.xlsx'
    $hwswPath = Join-Path $OutDir 'sample-eMASS-HW-SW-List.xlsx'
    $poamResult = (New-Object Vulnerator.Model.BusinessLogic.Reports.OpenXmlEmassPoamReportCreator).CreateEmassPoam($poamPath)
    Assert-That (($poamResult -eq 'Excel report creation successful') -and [System.IO.File]::Exists($poamPath)) ('eMASS POA&M export runs (got "' + $poamResult + '")')
    $hwswResult = (New-Object Vulnerator.Model.BusinessLogic.Reports.OpenXmlEmassHardwareSoftwareReportCreator).CreateHardwareSoftwareList($hwswPath)
    Assert-That (($hwswResult -eq 'Excel report creation successful') -and [System.IO.File]::Exists($hwswPath)) ('eMASS Hardware/Software export runs (got "' + $hwswResult + '")')
    $hwswReport = [int](Get-Scalar "SELECT COUNT(*) FROM RequiredReports WHERE DisplayedReportName = 'eMASS Hardware/Software List'")
    Assert-That ($hwswReport -eq 1) 'Hardware/Software report is registered once in the Reporting screen'
    $rarName = Get-Scalar 'SELECT DisplayedReportName FROM RequiredReports WHERE RequiredReport_ID = 2'
    Assert-That ($rarName -eq 'Risk Assessment Report') ('report 2 is the generic Risk Assessment Report (got "' + $rarName + '")')
    Assert-That ([int](Get-Scalar "SELECT COUNT(*) FROM RequiredReports WHERE DisplayedReportName LIKE '%Navy%'") -eq 0) 'no Navy-branded report remains'
    $rarPath = Join-Path $OutDir 'sample-Risk-Assessment-Report.xlsx'
    $rarResult = (New-Object Vulnerator.Model.BusinessLogic.Reports.OpenXmlRiskAssessmentReportCreator).CreateRiskAssessmentReport($rarPath)
    Assert-That (($rarResult -like '*successful*') -and [System.IO.File]::Exists($rarPath)) ('Risk Assessment Report export runs (got "' + $rarResult + '")')
}
catch {
    $script:failures.Add('Unhandled error: ' + $_.Exception.ToString())
    Write-Host ('ERROR ' + $_.Exception.ToString())
    Write-Annotation 'error' ('ERROR ' + $_.Exception.ToString() + ' AT ' + $_.InvocationInfo.PositionMessage)
}

Write-Host ''
if ($script:failures.Count -eq 0) {
    Write-Host 'All checklist import checks passed.'
    exit 0
}
Write-Host ([string]$script:failures.Count + ' check(s) failed.')
$logDir = Join-Path $binPath 'Logs'
if (Test-Path $logDir) { Get-ChildItem $logDir -Filter '*.txt' | Select-Object -First 1 | ForEach-Object { Write-Annotation 'warning' ('App log tail: ' + ((Get-Content $_.FullName -Tail 25) -join ' | ')) } }
exit 1
