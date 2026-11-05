# Checks the add-on mechanism with throw-away add-ons compiled here (none of them ship): a working add-on, one in a
# subfolder with its own dependency, and add-ons that must be skipped without stopping Vulnerator (throws while
# starting, needs a newer interface, needs a newer Vulnerator, not an add-on, wrong entry type, not a .NET file,
# duplicate id). Then checks the read-only data the add-ons get, the data-changed event, the menu pages and the
# Settings > Integrations section.
#
# Windows PowerShell 5.1, 64-bit (the build is x64), STA. Pure ASCII; no PowerShell 7 syntax.
# Usage: %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -File tools\tests\Test-AddOns.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'

$binPath = (Resolve-Path $BinDir).Path
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorAddOns_' + [Guid]::NewGuid().ToString('N'))
$addOnDir = Join-Path $workDir 'Add-ons'
$subDir = Join-Path $addOnDir 'nested'
[void][System.IO.Directory]::CreateDirectory($subDir)
$failures = New-Object System.Collections.Generic.List[string]

function Fail([string]$Message) {
    Write-Host ('FAIL ' + $Message)
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ('::error::' + ($Message -replace "`r?`n", ' ')) }
    exit 1
}
function Check([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host ('ok   ' + $Message) }
    else { Write-Host ('FAIL ' + $Message); $failures.Add($Message) }
}

try {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Fail 'the test needs an STA thread (Windows PowerShell 5.1 default)' }
    $contract = Join-Path $binPath 'Vulnerator.AddOns.dll'
    if (-not (Test-Path $contract)) { Fail 'Vulnerator.AddOns.dll is not in the program folder' }
    $shippedFolder = Join-Path $binPath 'Add-ons'
    Check (Test-Path (Join-Path $shippedFolder 'README.txt')) 'the release has an Add-ons folder with README.txt'
    Check (@(Get-ChildItem $binPath -Recurse -Filter '*.AddOn.dll').Count -eq 0) 'the release ships no add-ons'

    # Same set-up as Test-EntityFramework.ps1: the application's configuration, then the program's assemblies.
    [AppDomain]::CurrentDomain.SetData('APP_CONFIG_FILE', (Join-Path $binPath 'Vulnerator.exe.config'))
    Add-Type -AssemblyName System.Configuration
    $manager = [System.Configuration.ConfigurationManager]
    $manager.GetField('s_initState', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, 0)
    $manager.GetField('s_configSystem', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    ($manager.Assembly.GetTypes() | Where-Object { $_.FullName -eq 'System.Configuration.ClientConfigPaths' }).GetField('s_current', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    [System.IO.Directory]::SetCurrentDirectory($binPath)
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
    foreach ($name in 'Vulnerator.exe', 'Vulnerator.AddOns.dll', 'EntityFramework.dll', 'System.Data.SQLite.dll', 'System.Data.SQLite.EF6.dll', 'log4net.dll',
                      'ControlzEx.dll', 'Microsoft.Xaml.Behaviors.dll', 'MahApps.Metro.dll', 'MahApps.Metro.IconPacks.Core.dll', 'MahApps.Metro.IconPacks.Material.dll') {
        $path = Join-Path $binPath $name
        if (Test-Path $path) { [void][System.Reflection.Assembly]::LoadFrom($path) }
    }
    foreach ($dll in @(Get-ChildItem $binPath -Filter 'GalaSoft.MvvmLight*.dll')) { [void][System.Reflection.Assembly]::LoadFrom($dll.FullName) }
    # The app's binding redirects do not apply to this host: hand back the loaded copies.
    $redirect = @'
using System;
using System.Linq;
public static class AddOnTestRedirect
{
    public static void Install()
    {
        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
        {
            string name = new System.Reflection.AssemblyName(args.Name).Name;
            return AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == name);
        };
    }
}
'@
    Add-Type -TypeDefinition $redirect -ReferencedAssemblies 'System.Core.dll'
    [AddOnTestRedirect]::Install()

    # A scratch database with one checklist and one scan.
    $app = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Vulnerator' } | Select-Object -First 1
    $settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
    $defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
    $indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
    $database = Join-Path $workDir 'addons.sqlite'
    $indexer.SetValue($defaultSettings, $database, [object[]]@('Database'))
    $indexer.SetValue($defaultSettings, 'addon-test', [object[]]@('ActiveUser'))
    $indexer.SetValue($defaultSettings, 'UNCLASSIFIED', [object[]]@('EmassClassificationMarking'))
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)
    $file = New-Object Vulnerator.Model.Object.File ('multi-stig', 'Checklist', 'Ready', (Join-Path $fixtures 'multi-stig.ckl'), 'True')
    if ((New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($file, 'All') -ne 'Processed') { Fail 'fixture checklist did not import' }
    $scan = New-Object Vulnerator.Model.Object.File ('scan', 'ACAS - Nessus', 'Ready', (Join-Path $fixtures 'scan.nessus'), 'True')
    if ((New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($scan, 'All') -ne 'Processed') { Fail 'fixture scan did not import' }

    # Throw-away add-ons.
    $wpf = @([System.Windows.Controls.TextBlock].Assembly.Location, [System.Windows.UIElement].Assembly.Location,
             [System.Windows.DependencyObject].Assembly.Location, [System.Xaml.XamlReader].Assembly.Location)
    function Build([string]$Path, [string]$Source, [string[]]$Extra = @()) {
        $references = @($contract, 'System.dll', 'System.Core.dll') + $wpf + $Extra
        Add-Type -TypeDefinition $Source -OutputAssembly $Path -OutputType Library -ReferencedAssemblies $references
    }
    $template = @'
using System;
using Vulnerator.AddOns;
__ATTRIBUTE__
namespace __NS__
{
    public class Entry : IAddOn
    {
        public static IAddOnHost Host;
        public static int Changes;
        public string Id { get { return "__ID__"; } }
        public string Name { get { return "__NAME__"; } }
        public string Version { get { return "1.0.0"; } }
        public string Description { get { return "Test add-on (not shipped)."; } }
        public void Initialize(IAddOnHost host)
        {
            Host = host;
            host.DataChanged += (sender, e) => Changes++;
            __BODY__
        }
    }
    public class NotAnAddOn { }
}
'@
    function AddOnSource([string]$Ns, [string]$Id, [string]$Name, [string]$Body, [string]$Attribute = '') {
        if ($Attribute -eq '') { $Attribute = '[assembly: VulneratorAddOn(typeof(' + $Ns + '.Entry))]' }
        return $template.Replace('__ATTRIBUTE__', $Attribute).Replace('__NS__', $Ns).Replace('__ID__', $Id).Replace('__NAME__', $Name).Replace('__BODY__', $Body)
    }
    $pageBody = 'host.AddPage("Sample Dashboard", "ChartBar", () => new System.Windows.Controls.TextBlock { Text = "sample page" }); host.AddSettingsSection("Sample settings", () => new System.Windows.Controls.TextBlock { Text = "sample settings" }); host.Log.Info("started");'
    Build (Join-Path $addOnDir 'Sample.AddOn.dll') (AddOnSource 'TestSample' 'test.sample' 'Sample' $pageBody)

    $helper = Join-Path $subDir 'TestHelperLib.dll'
    Add-Type -TypeDefinition 'namespace TestHelperLib { public static class Util { public static string Value() { return "helper ok"; } } }' -OutputAssembly $helper -OutputType Library
    $nestedBody = 'Value = TestHelperLib.Util.Value(); host.AddPage("Nested Page", "NoSuchIconName", () => new System.Windows.Controls.TextBlock { Text = Value });'
    Build (Join-Path $subDir 'Nested.AddOn.dll') ((AddOnSource 'TestNested' 'test.nested' 'Nested' $nestedBody).Replace('public static int Changes;', 'public static int Changes; public static string Value;')) @($helper)

    Build (Join-Path $addOnDir 'Broken.AddOn.dll') (AddOnSource 'TestBroken' 'test.broken' 'Broken' 'host.AddPage("Broken Page", "Bug", () => null); throw new InvalidOperationException("boom");')
    Build (Join-Path $addOnDir 'Future.AddOn.dll') (AddOnSource 'TestFuture' 'test.future' 'Future' '' '[assembly: VulneratorAddOn(typeof(TestFuture.Entry), ApiVersion = 99)]')
    Build (Join-Path $addOnDir 'NeedsCore.AddOn.dll') (AddOnSource 'TestNeedsCore' 'test.needscore' 'NeedsCore' '' '[assembly: VulneratorAddOn(typeof(TestNeedsCore.Entry), MinimumCoreVersion = "99.0.0")]')
    Build (Join-Path $addOnDir 'Plain.AddOn.dll') (AddOnSource 'TestPlain' 'test.plain' 'Plain' '' '// no attribute')
    Build (Join-Path $addOnDir 'WrongType.AddOn.dll') (AddOnSource 'TestWrongType' 'test.wrongtype' 'WrongType' '' '[assembly: VulneratorAddOn(typeof(TestWrongType.NotAnAddOn))]')
    Build (Join-Path $addOnDir 'Zz.Duplicate.AddOn.dll') (AddOnSource 'TestDuplicate' 'test.sample' 'Duplicate' '')
    [System.IO.File]::WriteAllBytes((Join-Path $addOnDir 'Garbage.AddOn.dll'), [byte[]](1..200))
    # A dependency that is not an add-on and must not be loaded as one.
    Copy-Item $helper (Join-Path $addOnDir 'NotAnAddOnLibrary.dll')

    # Load them.
    $loaded = @([Vulnerator.Model.AddOns.AddOnManager]::LoadFrom($addOnDir))
    foreach ($entry in $loaded) { Write-Host ('     ' + [System.IO.Path]::GetFileName($entry.File) + ': ' + $entry.Summary) }
    $byFile = @{}
    foreach ($entry in $loaded) { $byFile[[System.IO.Path]::GetFileName($entry.File)] = $entry }
    Check ($loaded.Count -eq 9) ('9 add-on files found (got ' + $loaded.Count + ')')
    $expected = [ordered]@{
        'Sample.AddOn.dll' = 'Loaded'; 'Nested.AddOn.dll' = 'Loaded'; 'Broken.AddOn.dll' = 'Failed'; 'Future.AddOn.dll' = 'Skipped';
        'NeedsCore.AddOn.dll' = 'Skipped'; 'Plain.AddOn.dll' = 'Skipped'; 'WrongType.AddOn.dll' = 'Failed'; 'Zz.Duplicate.AddOn.dll' = 'Skipped'; 'Garbage.AddOn.dll' = 'Skipped'
    }
    foreach ($key in $expected.Keys) {
        $state = if ($byFile.ContainsKey($key)) { '' + $byFile[$key].State } else { 'missing' }
        Check ($state -eq $expected[$key]) ($key + ' is ' + $expected[$key] + ' (got ' + $state + ')')
    }
    Check ($byFile['Future.AddOn.dll'].Message -like '*newer Vulnerator*') 'Future: the message says a newer Vulnerator is needed'
    Check ($byFile['Broken.AddOn.dll'].Message -like '*boom*') 'Broken: the message carries the error'
    Check ($byFile['Broken.AddOn.dll'].Pages.Count -eq 0) 'Broken: the page it registered before failing is dropped'
    Check ($byFile['Zz.Duplicate.AddOn.dll'].Message -like '*already loaded*') 'Duplicate id: skipped with a clear message'
    Check ([TestNested.Entry]::Value -eq 'helper ok') 'Nested: its dependency in its own folder was found'

    # Read-only data.
    $hostApi = [TestSample.Entry]::Host
    Check ($hostApi.ApiVersion -eq [Vulnerator.AddOns.AddOnApi]::Version) 'host reports the interface version'
    Check (-not [string]::IsNullOrWhiteSpace($hostApi.CoreVersion)) ('host reports the core version (' + $hostApi.CoreVersion + ')')
    Check ($hostApi.ClassificationMarking -eq 'UNCLASSIFIED') 'host passes the classification marking'
    $dataFolder = $hostApi.DataFolder
    Check ((Test-Path $dataFolder) -and $dataFolder.StartsWith($workDir, [StringComparison]::OrdinalIgnoreCase) -and $dataFolder -like '*Add-on data*test.sample') ('data folder next to the database (' + $dataFolder + ')')

    $findings = @($hostApi.Data.GetFindings())
    $hardware = @($hostApi.Data.GetHardware())
    $direct = New-Object System.Data.SQLite.SQLiteConnection ([Vulnerator.Model.DataAccess.DatabaseBuilder]::ConnectionStringFor($database))
    $direct.Open()
    $command = $direct.CreateCommand()
    $command.CommandText = 'SELECT COUNT(*) FROM UniqueFindings'
    $findingRows = [int]$command.ExecuteScalar()
    $command.CommandText = 'SELECT COUNT(*) FROM Hardware'
    $hardwareRows = [int]$command.ExecuteScalar()
    $direct.Close()
    Write-Host ('     findings ' + $findings.Count + ' (database ' + $findingRows + '), hardware ' + $hardware.Count + ' (database ' + $hardwareRows + ')')
    Check ($findings.Count -gt 0 -and $findings.Count -eq $findingRows) 'GetFindings returns every finding, unfiltered'
    Check ($hardware.Count -gt 0 -and $hardware.Count -eq $hardwareRows) 'GetHardware returns every hardware asset'
    $severities = (@($findings | ForEach-Object { $_.Severity } | Sort-Object -Unique) -join ', ')
    Check (@($findings | Where-Object { $_.FindingType -eq 'CKL' -and $_.Severity -notin 'I', 'II', 'III' }).Count -eq 0) ('checklist findings have CAT I-III severities (all values: ' + $severities + ')')
    Check (@($findings | Where-Object { $_.Status -eq 'Ongoing' -or $_.Status -eq 'Completed' }).Count -eq 0) 'statuses use checklist wording (Open, Not a Finding, ...)'
    Check (@($findings | Where-Object { $_.FindingType -eq 'CKL' }).Count -gt 0 -and @($findings | Where-Object { $_.FindingType -eq 'ACAS' }).Count -gt 0) 'findings from both the checklist and the scan'
    Check (@($findings | Where-Object { $_.NistControls.Count -gt 0 }).Count -gt 0) 'findings carry NIST controls'
    $readOnlyRecord = $false
    try { $findings[0].Title = 'changed' } catch { $readOnlyRecord = $true }
    Check ($readOnlyRecord -and $findings[0].Title -ne 'changed') 'finding records cannot be changed'

    # The connection add-ons read through refuses writes.
    $ro = New-Object System.Data.SQLite.SQLiteConnection ([Vulnerator.Model.DataAccess.DatabaseBuilder]::ConnectionStringFor($database) + 'Read Only=True;')
    $ro.Open()
    $write = $ro.CreateCommand()
    $write.CommandText = "UPDATE UniqueFindings SET Comments = 'changed'"
    $refused = $false
    try { [void]$write.ExecuteNonQuery() } catch { $refused = $true }
    $ro.Close()
    Check $refused 'the read-only connection refuses writes'

    $lateRefused = $false
    try { $hostApi.AddPage('Late', 'Bug', [Func[object]] { 'x' }) } catch { $lateRefused = $true }
    Check $lateRefused 'pages cannot be added after Initialize'

    [Vulnerator.Model.AddOns.AddOnManager]::NotifyDataChanged()
    Check ([TestSample.Entry]::Changes -eq 1 -and [TestBroken.Entry]::Changes -eq 0) 'DataChanged reaches loaded add-ons only'

    # Menu and Settings.
    $pageList = @([Vulnerator.Model.AddOns.AddOnManager]::Pages)
    $pageInfo = 'pages ' + $pageList.Count + ' [' + (@($pageList | ForEach-Object { $_.Title }) -join ', ') + ']; per add-on: ' + (@($loaded | ForEach-Object { $_.Name + '=' + $_.State + '/' + $_.Pages.Count }) -join ', ')
    Write-Host ('     ' + $pageInfo)
    Check ($pageList.Count -eq 2) ('two add-on pages registered (' + $pageInfo + ')')
    $menu = New-Object MahApps.Metro.Controls.HamburgerMenu
    $items = New-Object MahApps.Metro.Controls.HamburgerMenuItemCollection
    foreach ($label in 'Vulnerability Management', 'Reporting', 'News') {
        $item = New-Object MahApps.Metro.Controls.HamburgerMenuIconItem
        $item.Label = $label
        [void]$items.Add($item)
    }
    $menu.ItemsSource = $items
    [Vulnerator.View.UI.AddOnUi]::AddPages($menu)
    $labels = @($items | ForEach-Object { $_.Label }) -join ' | '
    Write-Host ('     menu: ' + $labels)
    Check ($labels -eq 'Vulnerability Management | Reporting | Nested Page | Sample Dashboard | News') ('add-on pages go before News in file order; the broken one is left out (menu: ' + $labels + ')')
    Check ($items[2].Icon.Kind -eq [MahApps.Metro.IconPacks.PackIconMaterialKind]::PuzzleOutline -and $items[3].Icon.Kind -eq [MahApps.Metro.IconPacks.PackIconMaterialKind]::ChartBar) 'icons: the named one, else the default'
    Check ($items[2].Tag -is [Vulnerator.View.UI.AddOnViewHost]) 'pages are created on first display'
    $view = $null
    $viewError = ''
    try { $view = @($pageList | Where-Object { $_.Title -eq 'Sample Dashboard' })[0].CreateView.Invoke() } catch { $viewError = $_.Exception.Message }
    Check ($view -is [System.Windows.Controls.TextBlock] -and $view.Text -eq 'sample page') ('the add-on creates its page (' + $(if ($null -eq $view) { 'null ' + $viewError } else { $view.GetType().FullName }) + ')')

    $panel = New-Object System.Windows.Controls.StackPanel
    [Vulnerator.View.UI.AddOnUi]::FillIntegrations($panel)
    $boxes = @($panel.Children | Where-Object { $_ -is [System.Windows.Controls.GroupBox] })
    Check ($panel.Children.Count -eq 11 -and $boxes.Count -eq 1 -and $boxes[0].Header -eq 'Sample settings') ('Settings > Integrations lists every add-on file and the settings section (' + $panel.Children.Count + ' items)')

    # No add-ons folder at all: nothing loaded, no error.
    $none = @([Vulnerator.Model.AddOns.AddOnManager]::LoadFrom((Join-Path $workDir 'missing')))
    Check ($none.Count -eq 0) 'no Add-ons folder: nothing loaded, no error'

    if ($failures.Count -gt 0) { Fail ('' + $failures.Count + ' add-on check(s) failed: ' + ($failures -join '; ')) }
    Write-Host 'Add-on checks passed.'
    exit 0
}
catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Fail ('Add-on check failed: ' + $_.Exception.Message + ' / innermost: ' + $inner.GetType().FullName + ': ' + $inner.Message + ' at ' + $_.InvocationInfo.PositionMessage)
}
