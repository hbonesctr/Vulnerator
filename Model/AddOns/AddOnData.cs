using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using Vulnerator.AddOns;
using Vulnerator.Model.BusinessLogic.Reports;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.AddOns
{
    /// <summary>
    /// The add-ons' view of the data: every call opens its own read-only connection (SQLite refuses writes on it), so
    /// add-ons never share or hold Vulnerator's connection and cannot change the database.
    /// </summary>
    internal sealed class AddOnData : IFindingsData
    {
        private const string HardwareQuery = @"
SELECT H.Hardware_ID, H.DisplayedHostName, H.FQDN, H.NetBIOS, H.ScanIP, H.OperatingSystem, H.Manufacturer,
       H.ModelNumber, H.SerialNumber, H.Role, H.IsVirtualServer,
       (SELECT GROUP_CONCAT(GroupName, ', ') FROM (SELECT DISTINCT G.GroupName FROM HardwareGroups HG
            JOIN Groups G ON HG.Group_ID = G.Group_ID WHERE HG.Hardware_ID = H.Hardware_ID ORDER BY G.GroupName)) AS GroupNames
FROM Hardware H
ORDER BY H.DisplayedHostName";

        private static readonly string[] ListSeparator = { ", " };

        public IReadOnlyList<FindingRecord> GetFindings()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return new FindingRecord[0];
                return ReportFindings.LoadAll(connection).Select(ToRecord).ToList().AsReadOnly();
            }
        }

        public IReadOnlyList<HardwareRecord> GetHardware()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return new HardwareRecord[0];
                List<HardwareRecord> hardware = new List<HardwareRecord>();
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = HardwareQuery;
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            hardware.Add(new HardwareRecord
                            {
                                Id = reader.IsDBNull(0) ? 0 : Convert.ToInt64(reader.GetValue(0), CultureInfo.InvariantCulture),
                                HostName = Text(reader, 1),
                                Fqdn = Text(reader, 2),
                                NetBios = Text(reader, 3),
                                IpAddress = Text(reader, 4),
                                OperatingSystem = Text(reader, 5),
                                Manufacturer = Text(reader, 6),
                                Model = Text(reader, 7),
                                SerialNumber = Text(reader, 8),
                                Role = Text(reader, 9),
                                IsVirtual = IsTrue(Text(reader, 10)),
                                Groups = List(Text(reader, 11))
                            });
                        }
                    }
                }
                return hardware.AsReadOnly();
            }
        }

        /// <summary>A read-only connection to the current database, or null when no database is set up yet.</summary>
        private static SQLiteConnection OpenReadOnly()
        {
            string database = Properties.Settings.Default.Database;
            if (string.IsNullOrWhiteSpace(database) || database == "Undefined" || !File.Exists(database))
            { return null; }
            SQLiteConnection connection = new SQLiteConnection(DatabaseBuilder.ConnectionStringFor(database) + "Read Only=True;");
            connection.Open();
            return connection;
        }

        private static FindingRecord ToRecord(ReportFinding finding)
        {
            return new FindingRecord
            {
                FindingType = finding.FindingType,
                SourceName = finding.SourceName,
                SourceVersion = finding.SourceVersionRelease,
                HostName = finding.HostName,
                IpAddress = finding.IpAddress,
                SoftwareName = finding.SoftwareName,
                Asset = finding.Asset,
                VulnerabilityId = finding.GroupIdentifier,
                RuleId = finding.FullRuleIdentifier,
                Title = finding.Title,
                Severity = finding.Severity,
                RawSeverity = finding.RawSeverity,
                Status = ReportFinding.DisplayStatus(finding.Status),
                IsOpen = finding.IsOpen,
                MitigatedStatus = finding.MitigatedStatus,
                Description = finding.Description,
                CheckContent = finding.CheckContent,
                FixText = finding.FixText,
                FindingDetails = finding.FindingDetails,
                Comments = finding.Comments,
                SourceFile = finding.SourceFile,
                LastObserved = finding.LastObserved,
                Groups = List(finding.Groups),
                NistControls = List(finding.NistControls),
                Ccis = List(finding.Ccis)
            };
        }

        private static IReadOnlyList<string> List(string joined)
        {
            if (string.IsNullOrWhiteSpace(joined)) return new string[0];
            return joined.Split(ListSeparator, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList().AsReadOnly();
        }

        private static bool IsTrue(string value)
        {
            return value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("y", StringComparison.OrdinalIgnoreCase) || value == "1";
        }

        private static string Text(SQLiteDataReader reader, int ordinal)
        {
            return reader.IsDBNull(ordinal) ? string.Empty : Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture);
        }
    }
}
