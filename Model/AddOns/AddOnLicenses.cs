using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Vulnerator.Helper;

namespace Vulnerator.Model.AddOns
{
    /// <summary>One license the user entered.</summary>
    public sealed class StoredLicense
    {
        internal StoredLicense(string file, string text)
        {
            File = file;
            Text = text;
        }

        /// <summary>The .lic file in the licenses folder.</summary>
        public string File { get; }

        /// <summary>The license text, trimmed.</summary>
        public string Text { get; }

        /// <summary>A short, one-line preview for the Settings list.</summary>
        public string Preview
        {
            get
            {
                string firstLine = Text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
                firstLine = firstLine.Trim();
                return firstLine.Length > 40 ? firstLine.Substring(0, 40) + "..." : firstLine;
            }
        }
    }

    /// <summary>
    /// Stores the add-on licenses the user enters (pasted keys and .lic files) as .lic files in an "Add-on licenses"
    /// folder next to the database, so a portable copy keeps them. Vulnerator does not check licenses: each add-on
    /// verifies the ones meant for it. Nothing here contacts any server.
    /// </summary>
    public static class AddOnLicenses
    {
        /// <summary>Largest license accepted (a signed key or .lic file is a few hundred bytes).</summary>
        public const int MaxLength = 64 * 1024;

        private const string FolderName = "Add-on licenses";

        /// <summary>The folder add-on data and licenses go in: the database's folder, else %LOCALAPPDATA%\Vulnerator.</summary>
        public static string BaseFolder()
        {
            string baseFolder = null;
            try
            {
                string database = Properties.Settings.Default.Database;
                if (!string.IsNullOrWhiteSpace(database) && database != "Undefined")
                { baseFolder = Path.GetDirectoryName(Path.GetFullPath(database)); }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Add-ons: the database folder could not be determined.", exception); }
            if (string.IsNullOrWhiteSpace(baseFolder))
            { baseFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Vulnerator"); }
            return baseFolder;
        }

        public static string Folder => Path.Combine(BaseFolder(), FolderName);

        /// <summary>Every stored license, oldest first. Unreadable files are logged and left out.</summary>
        public static IReadOnlyList<StoredLicense> All()
        {
            List<StoredLicense> licenses = new List<StoredLicense>();
            string folder = Folder;
            if (!Directory.Exists(folder)) return licenses;
            foreach (FileInfo file in new DirectoryInfo(folder).GetFiles("*.lic").OrderBy(f => f.CreationTimeUtc).ThenBy(f => f.Name, StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    if (file.Length > MaxLength) continue;
                    string text = System.IO.File.ReadAllText(file.FullName, Encoding.UTF8).Trim();
                    if (text.Length > 0) licenses.Add(new StoredLicense(file.FullName, text));
                }
                catch (Exception exception)
                { LogWriter.LogErrorWithDebug("Add-ons: license file " + file.Name + " could not be read.", exception); }
            }
            return licenses;
        }

        /// <summary>The license texts, as add-ons see them.</summary>
        public static IReadOnlyList<string> Texts() => All().Select(l => l.Text).ToList().AsReadOnly();

        /// <summary>Stores a pasted license. Returns null when stored, else a short reason for the user.</summary>
        public static string Add(string text)
        {
            text = (text ?? string.Empty).Trim();
            if (text.Length == 0) return "Paste a license key first.";
            if (text.Length > MaxLength) return "That is too long to be a license key.";
            if (text.IndexOf('\0') >= 0) return "That does not look like a license key (it contains binary data).";
            if (All().Any(l => string.Equals(l.Text, text, StringComparison.Ordinal))) return "That license is already entered.";
            try
            {
                Directory.CreateDirectory(Folder);
                string file = Path.Combine(Folder, "license-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".lic");
                System.IO.File.WriteAllText(file, text + Environment.NewLine, new UTF8Encoding(false));
                LogWriter.LogStatusUpdate("Add-ons: license added (" + Path.GetFileName(file) + ").");
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: the license could not be saved.", exception);
                return "The license could not be saved: " + exception.Message;
            }
            AddOnManager.NotifyLicensesChanged();
            return null;
        }

        /// <summary>Reads a .lic file the user picked and stores its text. Returns null when stored, else a reason.</summary>
        public static string Import(string path)
        {
            try
            {
                FileInfo file = new FileInfo(path);
                if (!file.Exists) return "The file was not found.";
                if (file.Length > MaxLength) return "That file is too large to be a license.";
                return Add(System.IO.File.ReadAllText(file.FullName, Encoding.UTF8));
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: license file " + path + " could not be read.", exception);
                return "The file could not be read: " + exception.Message;
            }
        }

        /// <summary>Deletes a stored license. Returns null when removed, else a reason.</summary>
        public static string Remove(StoredLicense license)
        {
            try
            {
                // Only files inside the licenses folder are ever deleted.
                string folder = Path.GetFullPath(Folder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                string file = Path.GetFullPath(license.File);
                if (!file.StartsWith(folder, StringComparison.OrdinalIgnoreCase)) return "That license is not in the licenses folder.";
                if (System.IO.File.Exists(file)) System.IO.File.Delete(file);
                LogWriter.LogStatusUpdate("Add-ons: license removed (" + Path.GetFileName(file) + ").");
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Add-ons: the license could not be removed.", exception);
                return "The license could not be removed: " + exception.Message;
            }
            AddOnManager.NotifyLicensesChanged();
            return null;
        }
    }
}
