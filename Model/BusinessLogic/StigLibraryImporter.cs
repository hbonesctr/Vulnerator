using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Loads STIG benchmarks into the vulnerability library from a DISA STIG library zip (zips within zips), a single
    /// STIG zip, or one benchmark .xml (manual XCCDF or SCAP data stream).
    /// </summary>
    public class StigLibraryImporter
    {
        // Inside a library, SCAP content duplicates the manual benchmark, and OVAL / CPE / OCIL files are not benchmarks.
        private static readonly Regex SkippedInsideZip = new Regex(@"scap|oval|cpe|ocil", RegexOptions.IgnoreCase);

        public int Attempted { get; private set; }
        public int Parsed { get; private set; }
        public int Older { get; private set; }
        public int Failed { get; private set; }
        public int Rules { get; private set; }

        /// <summary>Called with the number of top-level items once the file is opened.</summary>
        public Action<int> TotalItems { get; set; }

        /// <summary>Called with each file name as it is ingested, and once per top-level item done (null).</summary>
        public Action<string> Progress { get; set; }

        public string Import(string path)
        {
            Attempted = Parsed = Older = Failed = Rules = 0;
            if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
            {
                using (ZipArchive zipArchive = ZipFile.OpenRead(path))
                {
                    TotalItems?.Invoke(zipArchive.Entries.Count);
                    foreach (ZipArchiveEntry entry in zipArchive.Entries)
                    {
                        HandleEntry(entry);
                        Progress?.Invoke(null);
                    }
                }
            }
            else
            {
                TotalItems?.Invoke(1);
                using (FileStream stream = File.OpenRead(path))
                { ReadBenchmark(stream, Path.GetFileName(path), true); }
                Progress?.Invoke(null);
            }
            string summary = $"Loaded {Parsed} STIG(s), {Rules} rule(s)" +
                             (Older > 0 ? $"; {Older} skipped (a newer release is already loaded)" : string.Empty) +
                             (Failed > 0 ? $"; {Failed} failed (see log)" : string.Empty) + ".";
            LogWriter.LogStatusUpdate(summary);
            return summary;
        }

        private void HandleEntry(ZipArchiveEntry entry)
        {
            try
            {
                if (string.IsNullOrEmpty(entry.Name) || SkippedInsideZip.IsMatch(entry.Name))
                { return; }
                if (entry.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    using (MemoryStream buffer = new MemoryStream())
                    {
                        using (Stream stream = entry.Open())
                        { stream.CopyTo(buffer); }
                        buffer.Position = 0;
                        using (ZipArchive inner = new ZipArchive(buffer, ZipArchiveMode.Read))
                        {
                            foreach (ZipArchiveEntry innerEntry in inner.Entries)
                            { HandleEntry(innerEntry); }
                        }
                    }
                }
                else if (entry.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                {
                    using (Stream stream = entry.Open())
                    { ReadBenchmark(stream, entry.Name, false); }
                }
            }
            catch (Exception exception)
            {
                Failed++;
                LogWriter.LogErrorWithDebug($"Unable to read '{entry.FullName}' from the STIG library.", exception);
            }
        }

        private void ReadBenchmark(Stream stream, string name, bool selectedDirectly)
        {
            Progress?.Invoke(name);
            RawStigReader reader = new RawStigReader();
            string result = reader.ReadRawStig(stream, name);
            if (result == RawStigReader.Skipped && !selectedDirectly)
            { return; } // some other XML file in the library
            Attempted++;
            switch (result)
            {
                case RawStigReader.Parsed:
                    {
                        Parsed++;
                        Rules += reader.RulesRead;
                        break;
                    }
                case RawStigReader.Older:
                    {
                        Older++;
                        break;
                    }
                default:
                    {
                        Failed++;
                        break;
                    }
            }
        }
    }
}
