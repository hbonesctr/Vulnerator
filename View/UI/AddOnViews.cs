using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MahApps.Metro.Controls;
using MahApps.Metro.IconPacks;
using Vulnerator.AddOns;
using Vulnerator.Helper;
using Vulnerator.Model.AddOns;

namespace Vulnerator.View.UI
{
    /// <summary>
    /// Shows an add-on's view, created the first time it is displayed. If the add-on fails to create it, a short
    /// message is shown instead and the error is logged; Vulnerator keeps running.
    /// </summary>
    public sealed class AddOnViewHost : ContentControl
    {
        private readonly AddOnView _view;
        private bool _created;

        public AddOnViewHost(AddOnView view)
        {
            _view = view;
            Focusable = false;
            HorizontalContentAlignment = HorizontalAlignment.Stretch;
            VerticalContentAlignment = VerticalAlignment.Stretch;
            Loaded += (sender, e) => Create();
        }

        private void Create()
        {
            if (_created) return;
            _created = true;
            try
            {
                object content = _view.CreateView();
                if (content == null) throw new InvalidOperationException("the add-on returned no view");
                Content = content;
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: " + _view.Owner.Name + " could not show '" + _view.Title + "'.", exception);
                Content = new TextBlock
                {
                    Margin = new Thickness(10),
                    TextWrapping = TextWrapping.Wrap,
                    Text = _view.Owner.Name + " could not show this page: " + exception.Message + Environment.NewLine + "Details are in the Vulnerator log."
                };
            }
        }
    }

    /// <summary>Adds add-on pages to the navigation menu and the Integrations section to Settings.</summary>
    public static class AddOnUi
    {
        /// <summary>Inserts each add-on page into the main menu, before News (or at the end).</summary>
        public static void AddPages(HamburgerMenu menu)
        {
            try
            {
                HamburgerMenuItemCollection items = menu.ItemsSource as HamburgerMenuItemCollection;
                if (items == null) return;
                int position = items.Count;
                for (int i = 0; i < items.Count; i++)
                {
                    HamburgerMenuItem item = items[i] as HamburgerMenuItem;
                    if (item != null && string.Equals(item.Label, "News", StringComparison.Ordinal))
                    { position = i; break; }
                }
                foreach (AddOnView page in AddOnManager.Pages)
                {
                    try
                    {
                        PackIconMaterialKind kind;
                        if (string.IsNullOrWhiteSpace(page.IconName) || !Enum.TryParse(page.IconName.Trim(), true, out kind))
                        { kind = PackIconMaterialKind.PuzzleOutline; }
                        items.Insert(position, new HamburgerMenuIconItem
                        {
                            Label = page.Title,
                            ToolTip = page.Title + " (" + page.Owner.Name + " add-on)",
                            Icon = new PackIconMaterial { Kind = kind, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center },
                            Tag = new AddOnViewHost(page)
                        });
                        position++;
                    }
                    catch (Exception exception)
                    { LogWriter.LogErrorWithDebug("Add-ons: the page '" + page.Title + "' of " + page.Owner.Name + " could not be added to the menu.", exception); }
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: pages could not be added to the menu.", exception); }
        }

        /// <summary>
        /// Fills the Settings &gt; Integrations panel: each add-on found, its state and license status, its settings
        /// sections, and (when an add-on loaded) the Licenses box. <paramref name="message"/> is shown above the box.
        /// </summary>
        public static void FillIntegrations(Panel panel, string message = null)
        {
            try
            {
                panel.Children.Clear();
                if (AddOnManager.AddOns.Count == 0)
                {
                    panel.Children.Add(Note("No add-ons are installed. Add-ons are *.AddOn.dll files placed in this folder: " + AddOnManager.Folder));
                    return;
                }
                foreach (LoadedAddOn addOn in AddOnManager.AddOns)
                {
                    string text = addOn.Summary;
                    string status = LicenseStatus(addOn);
                    if (!string.IsNullOrWhiteSpace(status)) text += Environment.NewLine + "License: " + status;
                    if (!string.IsNullOrWhiteSpace(addOn.Description)) text += Environment.NewLine + addOn.Description;
                    TextBlock line = Note(text);
                    if (addOn.State != AddOnState.Loaded) line.Foreground = Brushes.OrangeRed;
                    panel.Children.Add(line);
                    foreach (AddOnView section in addOn.SettingsSections)
                    {
                        panel.Children.Add(new GroupBox
                        {
                            Margin = new Thickness(5, 0, 5, 5),
                            Header = section.Title,
                            Content = new AddOnViewHost(section)
                        });
                    }
                }
                if (AddOnManager.AddOns.Any(a => a.State == AddOnState.Loaded))
                { panel.Children.Add(LicensesBox(panel, message)); }
                panel.Children.Add(Note("Add-ons folder: " + AddOnManager.Folder));
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: the Integrations section could not be shown.", exception); }
        }

        /// <summary>The licenses entered so far (with what each add-on says about them), and ways to add or remove one.</summary>
        private static GroupBox LicensesBox(Panel panel, string message)
        {
            StackPanel content = new StackPanel();
            IReadOnlyList<StoredLicense> licenses = AddOnLicenses.All();
            if (licenses.Count == 0)
            { content.Children.Add(Note("No licenses entered.")); }
            foreach (StoredLicense license in licenses)
            {
                List<string> descriptions = AddOnManager.AddOns
                    .Where(a => a.State == AddOnState.Loaded)
                    .Select(a => Describe(a, license.Text))
                    .Where(d => !string.IsNullOrWhiteSpace(d)).ToList();
                if (descriptions.Count == 0) descriptions.Add("Not recognized by any installed add-on.");
                DockPanel row = new DockPanel { Margin = new Thickness(0, 0, 0, 5), LastChildFill = true };
                Button remove = new Button { Content = "Remove", Margin = new Thickness(5, 0, 5, 0), VerticalAlignment = VerticalAlignment.Top, ToolTip = "Delete this license from this computer" };
                StoredLicense target = license;
                remove.Click += (sender, e) =>
                {
                    if (MessageBox.Show("Remove this license?" + Environment.NewLine + target.Preview, "Remove license", MessageBoxButton.YesNo, MessageBoxImage.Question) != MessageBoxResult.Yes) return;
                    string error = AddOnLicenses.Remove(target);
                    FillIntegrations(panel, error ?? "License removed.");
                };
                DockPanel.SetDock(remove, Dock.Right);
                row.Children.Add(remove);
                row.Children.Add(Note(license.Preview + Environment.NewLine + string.Join(Environment.NewLine, descriptions)));
                content.Children.Add(row);
            }

            TextBox key = new TextBox
            {
                Margin = new Thickness(5, 0, 5, 5),
                AcceptsReturn = true,
                TextWrapping = TextWrapping.Wrap,
                MinHeight = 50,
                MaxHeight = 150,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                ToolTip = "Paste a license key, then choose Add license"
            };
            Button add = new Button { Content = "Add license", Margin = new Thickness(5, 0, 5, 5) };
            add.Click += (sender, e) =>
            {
                string error = AddOnLicenses.Add(key.Text);
                FillIntegrations(panel, error ?? "License added.");
            };
            Button import = new Button { Content = "Import .lic file...", Margin = new Thickness(5, 0, 5, 5) };
            import.Click += (sender, e) =>
            {
                Microsoft.Win32.OpenFileDialog dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Import add-on license",
                    Filter = "License files (*.lic)|*.lic|All files (*.*)|*.*",
                    CheckFileExists = true,
                    Multiselect = false
                };
                if (dialog.ShowDialog() != true) return;
                string error = AddOnLicenses.Import(dialog.FileName);
                FillIntegrations(panel, error ?? "License imported.");
            };
            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal };
            buttons.Children.Add(add);
            buttons.Children.Add(import);
            content.Children.Add(Note("Paste a license key:"));
            content.Children.Add(key);
            content.Children.Add(buttons);
            if (!string.IsNullOrWhiteSpace(message))
            { content.Children.Add(Note(message)); }
            content.Children.Add(Note("Licenses are checked by each add-on on this computer; nothing is sent anywhere. Stored in: " + AddOnLicenses.Folder));
            return new GroupBox { Margin = new Thickness(5, 0, 5, 5), Header = "Licenses", Content = content };
        }

        private static string LicenseStatus(LoadedAddOn addOn)
        {
            IAddOnLicensing licensing = addOn.Instance as IAddOnLicensing;
            if (addOn.State != AddOnState.Loaded || licensing == null) return null;
            try
            { return licensing.LicenseStatus; }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: " + addOn.Name + " could not report its license status.", exception);
                return "could not be checked (see the log)";
            }
        }

        private static string Describe(LoadedAddOn addOn, string licenseText)
        {
            IAddOnLicensing licensing = addOn.Instance as IAddOnLicensing;
            if (licensing == null) return null;
            try
            { return licensing.DescribeLicense(licenseText); }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: " + addOn.Name + " could not check a license.", exception);
                return addOn.Name + ": could not check this license (see the log)";
            }
        }

        private static TextBlock Note(string text)
        {
            return new TextBlock { Margin = new Thickness(5, 0, 5, 5), TextWrapping = TextWrapping.Wrap, Text = text };
        }
    }
}
