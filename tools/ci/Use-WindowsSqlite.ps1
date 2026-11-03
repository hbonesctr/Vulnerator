# Points System.Data.SQLite 2.x at Windows' own SQLite (winsqlite3.dll in System32) instead of e_sqlite3.dll.
#
# Why: locked-down machines (endpoint protection) refuse to load native DLLs from user-writable folders such as the
# user profile, so an e_sqlite3.dll shipped next to Vulnerator.exe cannot load there. winsqlite3.dll is part of Windows,
# signed by Microsoft, updated by Windows Update, and loads from System32. System.Data.SQLite fixes the native library
# name at "e_sqlite3"; this rewrites that one module reference in the built System.Data.SQLite.dll (Mono.Cecil).
# The build is 64-bit: 32-bit winsqlite3 uses the stdcall convention, System.Data.SQLite expects cdecl.
#
# Windows PowerShell 5.1. Usage: powershell -File tools\ci\Use-WindowsSqlite.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'
trap {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Write-Host ('::error::Use-WindowsSqlite: ' + $_.Exception.Message + ' / ' + $inner.GetType().FullName + ': ' + $inner.Message + ' at ' + $_.InvocationInfo.PositionMessage)
    exit 1
}

$binPath = (Resolve-Path $BinDir).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) 'vulnerator-cecil'
if (-not (Test-Path (Join-Path $work 'Mono.Cecil.0.11.6'))) {
    $out = & nuget install Mono.Cecil -Version 0.11.6 -OutputDirectory $work -NonInteractive 2>&1 | Out-String
    Write-Host $out
}
Add-Type -Path (Join-Path $work 'Mono.Cecil.0.11.6\lib\net40\Mono.Cecil.dll')

$target = Join-Path $binPath 'System.Data.SQLite.dll'
$readerParameters = New-Object Mono.Cecil.ReaderParameters
$readerParameters.ReadWrite = $true
$assembly = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($target, $readerParameters)
try {
    $changed = 0
    foreach ($moduleReference in $assembly.MainModule.ModuleReferences) {
        if ($moduleReference.Name -eq 'e_sqlite3' -or $moduleReference.Name -eq 'e_sqlite3.dll') {
            $moduleReference.Name = 'winsqlite3'
            $changed++
        }
    }
    $pinvokes = @($assembly.MainModule.Types | ForEach-Object { $_.Methods } | Where-Object { $_.IsPInvokeImpl })
    $names = @($assembly.MainModule.ModuleReferences | ForEach-Object { $_.Name }) -join ', '
    if ($changed -eq 0 -and $names -notmatch 'winsqlite3') { throw "System.Data.SQLite.dll has no e_sqlite3 module reference (references: $names)" }
    $assembly.Write()
    Write-Host ("System.Data.SQLite.dll now uses winsqlite3 (module references: $names; $($pinvokes.Count) native calls).")
}
finally { $assembly.Dispose() }

foreach ($stray in 'e_sqlite3.dll', 'SQLite.Interop.dll', 'sqlite3.dll') {
    Get-ChildItem $binPath -Recurse -Filter $stray | Remove-Item -Force
}
