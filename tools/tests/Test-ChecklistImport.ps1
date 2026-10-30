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
    # Keep the app's log in memory so errors it catches and logs can be shown when a check fails.
    $script:memoryLog = [Activator]::CreateInstance($log4net.GetType('log4net.Appender.MemoryAppender'))
    $script:memoryLog.GetType().GetMethod('ActivateOptions').Invoke($script:memoryLog, $null)
    $configure = $log4net.GetType('log4net.Config.BasicConfigurator').GetMethod('Configure', [Type[]]@($log4net.GetType('log4net.Appender.IAppender')))
    if ($null -ne $configure) { [void]$configure.Invoke($null, [object[]]@($script:memoryLog)) }

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
    Assert-That ([int](Get-Scalar 'PRAGMA user_version') -eq 7) 'reference data version is 7 (Rev 5, CCI list 2026-07-14, CNSSI 1253)'
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
    $serverRelease = Get-Scalar "SELECT SourceRelease FROM VulnerabilitySources WHERE SourceName LIKE '%Test Server%'"
    Assert-That ([string]$serverRelease -eq '5') ('an older-release CKL does not move the STIG back to release 4 (got "' + $serverRelease + '")')

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
    Assert-That ($null -eq $builder::ToEmassStatus('Completed', '')) 'passing checks never become POA&M items (POAM-05)'
    Assert-That ($null -eq $builder::ToEmassStatus('Not Reviewed', '')) 'not-reviewed checks stay off the POA&M (R-19)'
    $cklbDate = Get-Scalar ("SELECT UF.FirstDiscovered FROM UniqueFindings UF JOIN Hardware H ON UF.Hardware_ID = H.Hardware_ID " +
        "JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE H.DiscoveredHostName = 'TESTHOST02' AND V.UniqueVulnerabilityIdentifier = 'SV-1002'")
    Assert-That (([datetime]$cklbDate).ToString('yyyy-MM-dd') -eq '2026-02-03') ('CKLB rule date (earlier of createdAt/updatedAt) is the first-discovered date (got "' + $cklbDate + '")')
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

    # --- Checklists without a host name (e.g. blank STIG baselines) ----------------------------
    $before = Get-Counts
    $hostsBefore = [int](Get-Scalar 'SELECT COUNT(*) FROM Hardware')
    $result = Import-Checklist (Join-Path $fixtures 'blank-host.ckl') 'TestGroup'
    $after = Get-Counts
    Assert-That ($result -eq 'Processed; STIG Baseline (no host)') ('checklist with no host imports as a STIG baseline (got "' + $result + '")')
    Assert-That ($after['UniqueFindings'] -eq $before['UniqueFindings']) 'a baseline checklist creates no findings'
    Assert-That ([int](Get-Scalar 'SELECT COUNT(*) FROM Hardware') -eq $hostsBefore) 'a baseline checklist creates no host'
    Assert-That ([int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-3002'") -eq 1) 'a baseline checklist adds its rules to the STIG library'
    $result = Import-Checklist (Join-Path $fixtures 'fqdn-only.ckl') 'TestGroup'
    $fqdnHost = [int](Get-Scalar "SELECT COUNT(*) FROM Hardware WHERE DiscoveredHostName = 'testhost03.example.test'")
    Assert-That (($result -eq 'Processed') -and ($fqdnHost -eq 1)) ('checklist with only an FQDN imports under the FQDN (got "' + $result + '")')

    # --- ACAS / Nessus ------------------------------------------------------------------------
    $nessusPath = Join-Path $fixtures 'scan.nessus'
    $nessusFile = New-Object Vulnerator.Model.Object.File ('scan', 'ACAS - Nessus', 'Ready', $nessusPath, 'True')
    $result = (New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($nessusFile, 'TestGroup')
    Assert-That ($result -eq 'Processed') ('.nessus with software enumeration (plugin 22869) imports (got "' + $result + '")')
    $ownerSql = 'SELECT H.DiscoveredHostName FROM UniqueFindings UF JOIN Hardware H ON UF.Hardware_ID = H.Hardware_ID ' +
        'JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE V.UniqueVulnerabilityIdentifier = @v'
    $owner = Get-Scalar $ownerSql @{ '@v' = '500002' }
    Assert-That ($owner -eq 'nessushost02.example.test') ('host without a hostname tag keeps its own findings, named by FQDN (got "' + $owner + '")')
    $highStatus = Get-Scalar 'SELECT UF.Status FROM UniqueFindings UF JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE V.UniqueVulnerabilityIdentifier = @v' @{ '@v' = '500001' }
    $infoStatus = Get-Scalar 'SELECT UF.Status FROM UniqueFindings UF JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE V.UniqueVulnerabilityIdentifier = @v' @{ '@v' = '19506' }
    Assert-That ($highStatus -eq 'Ongoing') ('High plugin is an open finding (got "' + $highStatus + '")')
    Assert-That ($infoStatus -eq 'Completed') ('informational plugin is not an open finding (got "' + $infoStatus + '")')
    $pyVersion = Get-Scalar "SELECT SoftwareVersion FROM Software WHERE DisplayedSoftwareName = 'python3-libs'"
    Assert-That ($pyVersion -eq '3.9.18-3.el9') ('RPM with digits in its name parses name and version (got "' + $pyVersion + '")')
    $mapped = [int](Get-Scalar ("SELECT COUNT(*) FROM SoftwareHardware SH JOIN Hardware H ON SH.Hardware_ID = H.Hardware_ID " +
        "WHERE H.DiscoveredHostName = 'nessushost01'"))
    Assert-That ($mapped -ge 3) ('enumerated packages are linked to their host (got ' + $mapped + ')')

    $finding = New-Object Vulnerator.Model.BusinessLogic.Reports.EmassPoamFinding
    $finding.VulnerabilityIdentifier = '19506'
    $finding.RawRisk = 'IV'
    $finding.RawStatus = 'Ongoing'
    $findingList = New-Object 'System.Collections.Generic.List[Vulnerator.Model.BusinessLogic.Reports.EmassPoamFinding]'
    $findingList.Add($finding)
    $poamItems = $builder::Build($findingList, (New-Object Vulnerator.Model.BusinessLogic.Reports.EmassPoamOptions))
    Assert-That ($poamItems.Count -eq 0) 'informational (raw risk IV) results never become POA&M items'

    # --- eMASS IG/AP import (local file, never in the repo) -----------------------------------
    $igapResult = [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import((Join-Path $fixtures 'igap-sample.xlsx'))
    Assert-That ($igapResult.StartsWith('Imported assessment procedures for 2 CCI(s)')) ('IG/AP export imports, CCI-NA row skipped (got "' + $igapResult + '")')
    $apSql = "SELECT NCCI.DOD_AssessmentProcedureMapping || '|' || NCCI.AssessmentProcedureText FROM NIST_ControlsCCIs NCCI JOIN CCIs C ON NCCI.CCI_ID = C.CCI_ID WHERE C.CCI_Number = '000015'"
    $ap = [string](Get-Scalar $apSql)
    Assert-That ($ap.StartsWith('AC-02(01).01|Determine if: synthetic procedure') -and $ap.Contains('Potential assessment methods and objectives')) ('CCI mapping carries the AP acronym and procedure (got "' + $ap.Substring(0, [Math]::Min(60, $ap.Length)) + '")')
    [void](Invoke-Sql 'PRAGMA user_version = 0')
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)
    $ap = [string](Get-Scalar $apSql)
    Assert-That ($ap.StartsWith('AC-02(01).01|')) 'imported procedures survive a reference data reload'

    # Generic CSV: other header names and order, quoted multi-line text, several CCIs in one cell, blank AP
    $csvResult = [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import((Join-Path $fixtures 'igap-generic.csv'))
    Assert-That ($csvResult.StartsWith('Imported assessment procedures for 3 CCI(s)') -and $csvResult.Contains('1 row(s) without a CCI skipped')) ('generic CSV imports (got "' + $csvResult + '")')
    $ap = [string](Get-Scalar $apSql)
    Assert-That ($ap.StartsWith('AC-02(01).01|Determine if: generic procedure') -and $ap.Contains('with "quotes", and a comma')) ('CSV procedure text replaces the old one; a blank AP keeps the existing AP (got "' + $ap.Substring(0, [Math]::Min(80, $ap.Length)) + '")')
    $ap366Sql = "SELECT NCCI.DOD_AssessmentProcedureMapping FROM NIST_ControlsCCIs NCCI JOIN CCIs C ON NCCI.CCI_ID = C.CCI_ID WHERE C.CCI_Number = '000366'"
    $ap366 = [string](Get-Scalar $ap366Sql)
    Assert-That ($ap366 -eq 'CM-06b.01') ('a cell listing several CCIs maps each of them (got "' + $ap366 + '")')
    $tsv = Join-Path $workDir 'procedures.tsv'
    [System.IO.File]::WriteAllText($tsv, ("CCI`tAP Acronym`r`nCCI-000366`tCM-06.TSV`r`n"))
    $tsvResult = [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import($tsv)
    $ap366 = [string](Get-Scalar $ap366Sql)
    Assert-That ($tsvResult.StartsWith('Imported assessment procedures for 1 CCI(s)') -and $ap366 -eq 'CM-06.TSV') ('tab-delimited file with only CCI and AP columns imports (got "' + $tsvResult + '" / "' + $ap366 + '")')
    $noCci = Join-Path $workDir 'no-cci.csv'
    [System.IO.File]::WriteAllText($noCci, "Control,Title`r`nAC-01,Policy`r`n")
    $noCciResult = [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import($noCci)
    Assert-That ($noCciResult.StartsWith('No assessment procedures found')) ('a file without CCI / AP columns is rejected clearly (got "' + $noCciResult + '")')

    # --- STIG library / benchmark import (synthetic benchmarks) -------------------------------
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $stigFixtures = Join-Path $fixtures 'stig'
    $innerDir = Join-Path $workDir 'inner'
    $outerDir = Join-Path $workDir 'outer'
    [void][System.IO.Directory]::CreateDirectory($innerDir)
    [void][System.IO.Directory]::CreateDirectory($outerDir)
    Copy-Item (Join-Path $stigFixtures 'U_Library_Test_STIG_V2R3_Manual-xccdf.xml') $innerDir
    Copy-Item (Join-Path $stigFixtures 'Library_SCAP_Test_SCAP_1-2_Benchmark.xml') (Join-Path $innerDir 'U_Library_Test_V2R3_STIG_SCAP_1-2_Benchmark.xml')
    [System.IO.File]::WriteAllText((Join-Path $innerDir 'STIG_unclass.xsl'), '<xsl/>')
    [System.IO.Compression.ZipFile]::CreateFromDirectory($innerDir, (Join-Path $outerDir 'U_Library_Test_V2R3_STIG.zip'))
    [System.IO.File]::WriteAllText((Join-Path $outerDir 'readme.txt'), 'synthetic library')
    $libraryZip = Join-Path $workDir 'U_SRG-STIG_Library_Test.zip'
    [System.IO.Compression.ZipFile]::CreateFromDirectory($outerDir, $libraryZip)

    $hostsBefore = [int](Get-Scalar 'SELECT COUNT(*) FROM Hardware')
    $importer = New-Object Vulnerator.Model.BusinessLogic.StigLibraryImporter
    $summary = $importer.Import($libraryZip)
    Assert-That ($importer.Parsed -eq 1 -and $importer.Failed -eq 0 -and $importer.Rules -eq 3) ('library zip (zip in zip) loads one STIG, 3 rules; SCAP copy skipped (got "' + $summary + '")')
    $ruleSql = 'SELECT VulnerabilityVersion || ''|'' || PrimaryRawRiskIndicator || ''|'' || VulnerabilityGroupIdentifier || ''|'' || SecondaryVulnerabilityIdentifier || ''|'' || CheckContent || ''|'' || IsDocumentable || ''|'' || VulnerabilityDescription FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = @v'
    $rule = [string](Get-Scalar $ruleSql @{ '@v' = 'SV-5001' })
    Assert-That ($rule -eq '2|I|V-5001|LIB-00-000010|Verify rule one.|false|Rule one discussion with & and <b> markup.') ('benchmark rule fields read (got "' + $rule + '")')
    $ruleCcis = [int](Get-Scalar 'SELECT COUNT(*) FROM VulnerabilitiesCCIs VC JOIN Vulnerabilities V ON VC.Vulnerability_ID = V.Vulnerability_ID WHERE V.UniqueVulnerabilityIdentifier = @v' @{ '@v' = 'SV-5001' })
    Assert-That ($ruleCcis -eq 2) ('rule mapped to both CCIs (got ' + $ruleCcis + ')')
    $sourceSql = "SELECT SourceVersion || '|' || SourceRelease FROM VulnerabilitySources WHERE SourceSecondaryIdentifier = 'Library_Test_STIG'"
    $source = [string](Get-Scalar $sourceSql)
    Assert-That ($source -eq '2|3') ('source version 2, release 3 (not the conventionsVersion) (got "' + $source + '")')
    Assert-That ([int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-6001'") -eq 0) 'SCAP content inside the library is not loaded'
    Assert-That ([int](Get-Scalar 'SELECT COUNT(*) FROM Hardware') -eq $hostsBefore) 'library import adds no hosts'

    $result = Import-Checklist (Join-Path $fixtures 'library-test.ckl') 'TestGroup'
    Assert-That ($result -eq 'Processed') ('checklist for the library STIG imports (got "' + $result + '")')
    Assert-That ([int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-5002'") -eq 1) 'checklist reuses the library rule (no duplicate)'

    $summary = $importer.Import((Join-Path $stigFixtures 'U_Library_Test_STIG_V2R4_Manual-xccdf.xml'))
    Assert-That ($summary.StartsWith('Loaded 1 STIG(s), 3 rule(s)')) ('newer release loads from a single benchmark file (got "' + $summary + '")')
    $revisions = [string](Get-Scalar "SELECT GROUP_CONCAT(VulnerabilityVersion) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-5001'")
    Assert-That ($revisions -eq '3') ('revised rule replaces the unused old revision (got "' + $revisions + '")')
    $kept = [string](Get-Scalar $statusSql @{ '@h' = 'LIBHOST01'; '@v' = 'SV-5002' })
    Assert-That ($kept -eq 'Ongoing') ('a rule dropped from the STIG is kept while a finding uses it (got "' + $kept + '")')
    Assert-That ([int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier IN ('SV-5003', 'SV-5004')") -eq 2) 'new and unchanged rules present'
    $orphans = [int](Get-Scalar 'SELECT (SELECT COUNT(*) FROM VulnerabilitiesCCIs WHERE Vulnerability_ID NOT IN (SELECT Vulnerability_ID FROM Vulnerabilities)) + (SELECT COUNT(*) FROM VulnerabilitiesVulnerabilitySources WHERE Vulnerability_ID NOT IN (SELECT Vulnerability_ID FROM Vulnerabilities))')
    Assert-That ($orphans -eq 0) ('pruned rules leave no orphan mappings (got ' + $orphans + ')')
    $source = [string](Get-Scalar $sourceSql)
    Assert-That ($source -eq '2|4') ('source moves to release 4 (got "' + $source + '")')

    $summary = $importer.Import((Join-Path $stigFixtures 'U_Library_Test_STIG_V2R3_Manual-xccdf.xml'))
    $revisions = [string](Get-Scalar "SELECT GROUP_CONCAT(VulnerabilityVersion) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-5001'")
    Assert-That ($importer.Older -eq 1 -and $revisions -eq '3' -and [string](Get-Scalar $sourceSql) -eq '2|4') ('an older release does not overwrite a newer one (got "' + $summary + '")')
    $result = Import-Checklist (Join-Path $fixtures 'library-test.ckl') 'TestGroup'
    $source = [string](Get-Scalar $sourceSql)
    $kept = [string](Get-Scalar $statusSql @{ '@h' = 'LIBHOST01'; '@v' = 'SV-5002' })
    $r4Date = [string](Get-Scalar "SELECT typeof(PublishedDate) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-5001'")
    Assert-That ($result -eq 'Processed' -and $source -eq '2|4' -and $kept -eq 'Ongoing' -and $r4Date -eq 'integer') ('a release-3 checklist after the release-4 library keeps release 4 and its findings (got "' + $result + '", ' + $source + ', ' + $kept + ', ' + $r4Date + ')')

    $summary = $importer.Import((Join-Path $stigFixtures 'Library_SCAP_Test_SCAP_1-2_Benchmark.xml'))
    $scapRule = [string](Get-Scalar "SELECT VulnerabilityVersion || '|' || VulnerabilityGroupIdentifier || '|' || VulnerabilityTitle FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = 'SV-6001'")
    Assert-That ($importer.Parsed -eq 1 -and $scapRule -eq '7|V-6001|Automated rule must be enforced.') ('SCAP 1.2 data stream (XCCDF 1.2 ids) loads when selected directly (got "' + $summary + '" / "' + $scapRule + '")')
    $scapSource = [string](Get-Scalar "SELECT COUNT(*) FROM VulnerabilitySources WHERE SourceSecondaryIdentifier = 'Library_SCAP_Test'")
    Assert-That ($scapSource -eq '1') 'XCCDF 1.2 benchmark id prefix removed'
    $notStig = Join-Path $workDir 'not-a-stig.xml'
    [System.IO.File]::WriteAllText($notStig, '<root/>')
    $summary = $importer.Import($notStig)
    Assert-That ($importer.Failed -eq 1 -and $importer.Parsed -eq 0) ('an XML file that is not a benchmark is reported, not loaded (got "' + $summary + '")')

    # --- SCAP / SCC XCCDF results ----------------------------------------------------------------
    $xccdfFixtures = Join-Path $fixtures 'xccdf'
    function Import-Xccdf {
        param([string]$Name)
        $path = Join-Path $xccdfFixtures $Name
        $file = New-Object Vulnerator.Model.Object.File ([System.IO.Path]::GetFileNameWithoutExtension($path), 'SCAP Benchmark', 'Ready', $path, 'True')
        $script:xccdfReader = New-Object Vulnerator.Model.BusinessLogic.XccdfReader
        return $script:xccdfReader.ReadXccdfFile($file, 'TestGroup')
    }
    $result = Import-Xccdf 'scc5-results.xml'
    Assert-That ($result -eq 'Processed' -and $script:xccdfReader.FindingsRead -eq 3) ('SCC 5 XCCDF 1.2 results import; notselected rule skipped (got "' + $result + '", ' + $script:xccdfReader.FindingsRead + ' findings)')
    $fail = [string](Get-Scalar $statusSql @{ '@h' = 'SCCHOST01'; '@v' = 'SV-8001' })
    $pass = [string](Get-Scalar $statusSql @{ '@h' = 'SCCHOST01'; '@v' = 'SV-8002' })
    $notChecked = [string](Get-Scalar $statusSql @{ '@h' = 'SCCHOST01'; '@v' = 'SV-8004' })
    Assert-That ($fail -eq 'Ongoing' -and $pass -eq 'Completed' -and $notChecked -eq 'Not Reviewed') ('fail / pass / notchecked map to Ongoing / Completed / Not Reviewed (got ' + $fail + ' / ' + $pass + ' / ' + $notChecked + ')')
    $output = [string](Get-Scalar 'SELECT UF.ToolGeneratedOutput FROM UniqueFindings UF JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE V.UniqueVulnerabilityIdentifier = @v' @{ '@v' = 'SV-8001' })
    Assert-That ($output.Contains('Result: fail') -and $output.Contains('Message: Value found: 0') -and $output.Contains('scc:5.10')) ('tool output keeps result, message and scanner (got "' + $output + '")')
    $hostInfo = [string](Get-Scalar "SELECT H.FQDN || '|' || (SELECT GROUP_CONCAT(IP.IP_Address) FROM Hardware_IP_Addresses HI JOIN IP_Addresses IP ON HI.IP_Address_ID = IP.IP_Address_ID WHERE HI.Hardware_ID = H.Hardware_ID) FROM Hardware H WHERE H.DiscoveredHostName = 'SCCHOST01'")
    Assert-That ($hostInfo -eq 'scchost01.example.test|10.9.8.7') ('host FQDN and IP from target facts; loopback dropped (got "' + $hostInfo + '")')
    $inGroup = [int](Get-Scalar "SELECT COUNT(*) FROM HardwareGroups HG JOIN Hardware H ON HG.Hardware_ID = H.Hardware_ID JOIN Groups G ON HG.Group_ID = G.Group_ID WHERE H.DiscoveredHostName = 'SCCHOST01' AND G.GroupName = 'TestGroup'")
    Assert-That ($inGroup -eq 1) 'host placed in the selected group'
    $score = [string](Get-Scalar "SELECT S.Score || '|' || S.ScanProfile || '|' || S.ScanUser FROM SCAP_Scores S JOIN Hardware H ON S.Hardware_ID = H.Hardware_ID WHERE H.DiscoveredHostName = 'SCCHOST01'")
    Assert-That ($score -eq '50|MAC-1_Classified|TESTDOMAIN\scanner') ('SCC default score recorded (got "' + $score + '")')
    $before = [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings')
    $result = Import-Xccdf 'scc5-results.xml'
    Assert-That ($result -eq 'Processed' -and [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings') -eq $before) 're-importing the same results adds no findings'

    $result = Import-Xccdf 'legacy-xccdf11-results.xml'
    $legacy = [string](Get-Scalar $statusSql @{ '@h' = 'LEGACYHOST'; '@v' = 'SV-7001' })
    Assert-That ($result -eq 'Processed' -and $legacy -eq 'Ongoing' -and $script:xccdfReader.UnmatchedResults -eq 1) ('XCCDF 1.1 results (host from <target>) import; result for an unknown rule skipped (got "' + $result + '", ' + $legacy + ', ' + $script:xccdfReader.UnmatchedResults + ' unmatched)')
    $result = Import-Xccdf 'oval-results.xml'
    Assert-That ($result -eq 'Report Type (OVAL) Not Supported') ('OVAL results are refused clearly (got "' + $result + '")')
    $benchmarkOnly = New-Object Vulnerator.Model.Object.File ('benchmark', 'SCAP Benchmark', 'Ready', (Join-Path $stigFixtures 'U_Library_Test_STIG_V2R4_Manual-xccdf.xml'), 'True')
    $result = (New-Object Vulnerator.Model.BusinessLogic.XccdfReader).ReadXccdfFile($benchmarkOnly, 'TestGroup')
    Assert-That ($result -eq 'Failed; No XCCDF Results') ('a benchmark without results points to the STIG library (got "' + $result + '")')

    # --- ACAS / Tenable.sc CSV -------------------------------------------------------------------
    $csvPath = Join-Path $fixtures 'acas-vulnerability-detail.csv'
    $csvFile = New-Object Vulnerator.Model.Object.File ('acas-vulnerability-detail', 'ACAS - CSV', 'Ready', $csvPath, 'True')
    $csvReader = New-Object Vulnerator.Model.BusinessLogic.AcasCsvReader
    $result = $csvReader.ReadAcasCsvFile($csvFile, 'TestGroup')
    Assert-That ($result -eq 'Processed' -and $csvReader.RowsRead -eq 4) ('Tenable.sc CSV imports (multi-line quoted output, control character) (got "' + $result + '", ' + $csvReader.RowsRead + ' rows)')
    $critical = [string](Get-Scalar $statusSql @{ '@h' = 'csvhost01.example.test'; '@v' = '97833' })
    $info = [string](Get-Scalar $statusSql @{ '@h' = 'csvhost01.example.test'; '@v' = '19506' })
    $medium = [string](Get-Scalar $statusSql @{ '@h' = '10.20.30.41'; '@v' = '42873' })
    Assert-That ($critical -eq 'Ongoing' -and $info -eq 'Completed' -and $medium -eq 'Ongoing') ('CSV statuses match .nessus handling; host without a name filed by IP (got ' + $critical + ' / ' + $info + ' / ' + $medium + ')')
    $csvVuln = [string](Get-Scalar "SELECT PrimaryRawRiskIndicator || '|' || VulnerabilityVersion || '|' || PublishedDate FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = '97833'")
    Assert-That ($csvVuln.StartsWith('I|1|2017/03/14')) ('CSV plugin risk, revision and dates read (got "' + $csvVuln + '")')
    $csvHost = [string](Get-Scalar "SELECT NetBIOS || '|' || ScanIP FROM Hardware WHERE DiscoveredHostName = 'csvhost01.example.test'")
    Assert-That ($csvHost -eq 'CSVHOST01|10.20.30.40') ('NetBIOS domain prefix dropped; scan IP kept (got "' + $csvHost + '")')
    $csvGroup = [int](Get-Scalar "SELECT COUNT(*) FROM HardwareGroups HG JOIN Hardware H ON HG.Hardware_ID = H.Hardware_ID JOIN Groups G ON HG.Group_ID = G.Group_ID WHERE H.DiscoveredHostName = 'csvhost01.example.test' AND G.GroupName = 'TestGroup'")
    Assert-That ($csvGroup -eq 1) 'CSV hosts placed in the selected group'
    $output = [string](Get-Scalar "SELECT UF.ToolGeneratedOutput FROM UniqueFindings UF JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID WHERE V.UniqueVulnerabilityIdentifier = '97833'")
    Assert-That ($output.StartsWith('The remote host is missing a "synthetic" update,') -and -not $output.StartsWith('Plugin Output')) ('plugin output kept without the "Plugin Output:" prefix (got "' + $output + '")')
    $notCsv = Join-Path $workDir 'not-acas.csv'
    [System.IO.File]::WriteAllText($notCsv, "Name,Value`r`nA,1`r`n")
    $result = (New-Object Vulnerator.Model.BusinessLogic.AcasCsvReader).ReadAcasCsvFile((New-Object Vulnerator.Model.Object.File ('not-acas', 'ACAS - CSV', 'Ready', $notCsv, 'True')), 'TestGroup')
    Assert-That ($result -eq 'Failed; Not An ACAS CSV') ('a CSV without plugin / host columns is refused clearly (got "' + $result + '")')

    # --- CKL export (round trip) -----------------------------------------------------------------
    $hardware = New-Object Vulnerator.Model.Entity.Hardware
    $hardware.Hardware_ID = [long](Get-Scalar "SELECT Hardware_ID FROM Hardware WHERE DiscoveredHostName = 'LIBHOST01'")
    $hardware.DisplayedHostName = 'LIBHOST01'
    $stigSource = New-Object Vulnerator.Model.Entity.VulnerabilitySource
    $stigSource.VulnerabilitySource_ID = [long](Get-Scalar "SELECT VulnerabilitySource_ID FROM VulnerabilitySources WHERE SourceSecondaryIdentifier = 'Library_Test_STIG'")
    $stigSource.SourceName = 'Library Test STIG'
    $exportDir = Join-Path $workDir 'ckl-export'
    [void][System.IO.Directory]::CreateDirectory($exportDir)
    $cklPath = (New-Object Vulnerator.Model.BusinessLogic.CklCreator).CreateCklFromHardware($hardware, $stigSource, $exportDir)
    Assert-That ([System.IO.File]::Exists($cklPath)) ('CKL written (got "' + $cklPath + '")')
    $ckl = New-Object System.Xml.XmlDocument
    $ckl.LoadXml([System.IO.File]::ReadAllText($cklPath))
    $vulns = @($ckl.SelectNodes('/CHECKLIST/STIGS/iSTIG/VULN'))
    Assert-That ($vulns.Count -eq 4) ('every rule of the STIG is in the checklist, one revision each (got ' + $vulns.Count + ')')
    $hostNode = $ckl.SelectSingleNode('/CHECKLIST/ASSET')
    Assert-That ($hostNode.HOST_NAME -eq 'LIBHOST01' -and $hostNode.HOST_IP -eq '10.1.2.9') ('asset from the host record (got "' + $hostNode.HOST_NAME + '" / "' + $hostNode.HOST_IP + '")')
    $releaseInfo = $ckl.SelectSingleNode("//SI_DATA[SID_NAME='releaseinfo']/SID_DATA").InnerText
    Assert-That ($releaseInfo -eq 'Release: 4 Benchmark Date: 01 May 2026') ('release info in STIG Viewer form (got "' + $releaseInfo + '")')
    $v5002 = $ckl.SelectSingleNode("//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='V-5002']]")
    Assert-That ($v5002.STATUS -eq 'Open' -and $v5002.FINDING_DETAILS -eq 'Account management is manual.' -and $v5002.COMMENTS -eq 'Ticket 42 opened.') ('host result, details and comments exported (got "' + $v5002.STATUS + '")')
    $v5001 = $ckl.SelectSingleNode("//VULN[STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='V-5001']]")
    $v5001Rule = $v5001.SelectSingleNode("STIG_DATA[VULN_ATTRIBUTE='Rule_ID']/ATTRIBUTE_DATA").InnerText
    $v5001Ccis = @($v5001.SelectNodes("STIG_DATA[VULN_ATTRIBUTE='CCI_REF']")).Count
    Assert-That ($v5001.STATUS -eq 'Not_Reviewed' -and $v5001Rule -eq 'SV-5001r3_rule' -and $v5001Ccis -eq 2) ('rule without a result is Not_Reviewed, current revision, both CCIs (got ' + $v5001.STATUS + ', ' + $v5001Rule + ', ' + $v5001Ccis + ')')
    $result = Import-Checklist $cklPath 'TestGroup'
    $roundTrip = [string](Get-Scalar $statusSql @{ '@h' = 'LIBHOST01'; '@v' = 'SV-5002' })
    $rulesAfter = [int](Get-Scalar "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier LIKE 'SV-500%'")
    Assert-That ($result -eq 'Processed' -and $roundTrip -eq 'Ongoing' -and $rulesAfter -eq 4) ('exported CKL re-imports without new rules or changed results (got "' + $result + '", ' + $roundTrip + ', ' + $rulesAfter + ' rules)')
    $notIgap = Join-Path $workDir 'not-igap.xlsx'
    [System.IO.File]::WriteAllText($notIgap, 'not a workbook')
    $bad = [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import($notIgap)
    Assert-That ($bad.StartsWith('Could not open the file')) ('an unreadable (e.g. label-encrypted) file gets a clear message (got "' + $bad + '")')
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
if ($null -ne $script:memoryLog) {
    $logged = @($script:memoryLog.GetEvents() | Where-Object { $_.Level.Name -eq 'ERROR' } | Select-Object -First 6)
    foreach ($logEvent in $logged) {
        $detail = if ($null -ne $logEvent.ExceptionObject) { $logEvent.ExceptionObject.ToString() } else { '' }
        Write-Annotation 'error' ('App logged: ' + $logEvent.RenderedMessage + ' ' + $detail)
    }
}
$logDir = Join-Path $binPath 'Logs'
if (Test-Path $logDir) { Get-ChildItem $logDir -Filter '*.txt' | Select-Object -First 1 | ForEach-Object { Write-Annotation 'warning' ('App log tail: ' + ((Get-Content $_.FullName -Tail 25) -join ' | ')) } }
exit 1
