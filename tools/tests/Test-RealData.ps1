# Imports every checklist and scan in a folder with Vulnerator's real importers, into a throwaway
# database, and prints one line per file (status, host, findings). Nothing is sent anywhere and your
# Vulnerator database is not touched. Use it to check real files before relying on a build.
#
# Usage (from the unzipped build folder, Windows PowerShell 5.1):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-RealData.ps1 -InputDir "C:\path\to\files"
#   add -IgApFile "C:\path\to\IGAPsExport.xlsx" to also try the eMASS IG/AP import
# Supported: *.ckl, *.cklb, *.nessus. Pure ASCII; no PowerShell 7 syntax.
param(
    [Parameter(Mandatory = $true)][string]$InputDir,
    [string]$BinDir = '',
    [string]$IgApFile = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The build is 32-bit (x86): relaunch in 32-bit Windows PowerShell when started from the 64-bit one.
if ([IntPtr]::Size -eq 8) {
    $ps32 = Join-Path $env:SystemRoot 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-InputDir', $InputDir)
    if ($BinDir -ne '') { $relaunch += @('-BinDir', $BinDir) }
    if ($IgApFile -ne '') { $relaunch += @('-IgApFile', $IgApFile) }
    & $ps32 @relaunch
    exit $LASTEXITCODE
}

if ($BinDir -eq '') { $BinDir = $PSScriptRoot }
$binPath = (Resolve-Path $BinDir).Path
$inputPath = (Resolve-Path $InputDir).Path
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorRealData_' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($workDir)
$dbPath = Join-Path $workDir 'realdata.sqlite'

Add-Type -AssemblyName System.Configuration
[System.IO.Directory]::SetCurrentDirectory($binPath)
$app = [System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'Vulnerator.exe'))
[void][System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'System.Data.SQLite.dll'))
$settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
$defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
$indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
$indexer.SetValue($defaultSettings, $dbPath, [object[]]@('Database'))
$indexer.SetValue($defaultSettings, 'real-data-test', [object[]]@('ActiveUser'))
[void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)

function Get-Scalar {
    param([string]$Sql)
    $connection = New-Object System.Data.SQLite.SQLiteConnection ('Data Source=' + $dbPath + ';Version=3;')
    $connection.Open()
    try { $command = $connection.CreateCommand(); $command.CommandText = $Sql; return $command.ExecuteScalar() }
    finally { $connection.Dispose() }
}

$files = @(Get-ChildItem -LiteralPath $inputPath -Recurse -File | Where-Object { @('.ckl', '.cklb', '.nessus') -contains $_.Extension.ToLowerInvariant() })
Write-Host ('Importing ' + $files.Count + ' file(s) from ' + $inputPath + ' into a scratch database')
Write-Host ''
$failed = 0
foreach ($item in $files) {
    $before = [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings')
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $extension = $item.Extension.ToLowerInvariant()
    if ($extension -eq '.nessus') {
        $file = New-Object Vulnerator.Model.Object.File ($item.BaseName, 'ACAS - Nessus', 'Ready', $item.FullName, 'True')
        $status = (New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($file, 'All')
    }
    else {
        $file = New-Object Vulnerator.Model.Object.File ($item.BaseName, 'Checklist', 'Ready', $item.FullName, 'True')
        if ($extension -eq '.cklb') { $status = (New-Object Vulnerator.Model.BusinessLogic.CklbReader).ReadCklbFile($file, 'All') }
        else { $status = (New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($file, 'All') }
    }
    $watch.Stop()
    $added = [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings') - $before
    if ($status -ne 'Processed') { $failed++ }
    Write-Host ('{0,-34} {1,7} findings {2,6:N1}s  {3}' -f $status, $added, $watch.Elapsed.TotalSeconds, $item.Name)
}

if ($IgApFile -ne '') {
    $igapPath = (Resolve-Path $IgApFile).Path
    Write-Host ''
    Write-Host ('eMASS IG/AP export: ' + [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import($igapPath))
}

Write-Host ''
Write-Host ('Hosts: ' + (Get-Scalar 'SELECT COUNT(*) FROM Hardware') + '; findings: ' + (Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings') +
    '; open: ' + (Get-Scalar "SELECT COUNT(*) FROM UniqueFindings WHERE Status = 'Ongoing'") + '; software: ' + (Get-Scalar 'SELECT COUNT(*) FROM Software'))
Write-Host ('Scratch database (delete when done): ' + $dbPath)
Write-Host ('Failures are explained in the Vulnerator log: ' + [string]$indexer.GetValue($defaultSettings, [object[]]@('LogPath')))
if ($failed -gt 0) { exit 1 }
exit 0
