using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Reflection;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Imports an eMASS "IG/APs" export (Control Number, AP Acronym, CCI, CCI Definition, Assessment Procedures,
    /// Potential Assessment Methods and Objectives) into the local database. The data is kept in its own table and
    /// re-applied to the CCI-to-control mappings whenever the reference data reloads, so it is loaded once per
    /// machine from the user's own export and never ships with Vulnerator.
    /// </summary>
    public static class EmassAssessmentProcedureImporter
    {
        private const string StoredProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";

        /// <summary>Imports the workbook; returns a one-line result for the user.</summary>
        public static string Import(string path)
        {
            List<string[]> rows;
            try
            { rows = ReadRows(path); }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to open IG/AP export '{path}'.", exception);
                return "Could not open the file. If it carries a sensitivity label with encryption, save an unprotected copy " +
                       "(or CSV) in Excel and import that.";
            }

            int header = rows.FindIndex(r => r.Any(c => Is(c, "AP Acronym")) && r.Any(c => Is(c, "CCI")));
            if (header < 0)
            { return "This is not an eMASS IG/AP export: no header row with \"AP Acronym\" and \"CCI\" was found."; }
            int colControl = Array.FindIndex(rows[header], c => Is(c, "Control Number"));
            int colAp = Array.FindIndex(rows[header], c => Is(c, "AP Acronym"));
            int colCci = Array.FindIndex(rows[header], c => Is(c, "CCI"));
            int colProcedure = Array.FindIndex(rows[header], c => Is(c, "Assessment Procedures"));
            int colMethods = Array.FindIndex(rows[header], c => Is(c, "Potential Assessment Methods and Objectives"));
            if (colProcedure < 0)
            { return "This IG/AP export has no \"Assessment Procedures\" column."; }

            int imported = 0, skipped = 0, applied;
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction transaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    command.CommandText = "DELETE FROM EmassAssessmentProcedures;";
                    command.ExecuteNonQuery();
                    command.CommandText =
                        "INSERT OR REPLACE INTO EmassAssessmentProcedures (CCI_Number, ControlNumber, AP_Acronym, AssessmentProcedure, AssessmentMethods, ImportedOn) " +
                        "VALUES (@CCI, @Control, @AP, @Procedure, @Methods, @ImportedOn);";
                    SQLiteParameter cci = command.Parameters.Add("@CCI", System.Data.DbType.String);
                    SQLiteParameter control = command.Parameters.Add("@Control", System.Data.DbType.String);
                    SQLiteParameter ap = command.Parameters.Add("@AP", System.Data.DbType.String);
                    SQLiteParameter procedure = command.Parameters.Add("@Procedure", System.Data.DbType.String);
                    SQLiteParameter methods = command.Parameters.Add("@Methods", System.Data.DbType.String);
                    command.Parameters.AddWithValue("@ImportedOn", DateTime.Now);
                    for (int i = header + 1; i < rows.Count; i++)
                    {
                        string number = Cell(rows[i], colCci).Trim();
                        // "CCI-NA" rows are control-level procedures with no CCI to attach them to.
                        if (!number.StartsWith("CCI-", StringComparison.OrdinalIgnoreCase) || !char.IsDigit(number.LastOrDefault()))
                        { skipped++; continue; }
                        cci.Value = number.Substring(4);
                        control.Value = Cell(rows[i], colControl).Trim();
                        ap.Value = Cell(rows[i], colAp).Trim();
                        procedure.Value = Cell(rows[i], colProcedure).Trim();
                        methods.Value = Cell(rows[i], colMethods).Trim();
                        command.ExecuteNonQuery();
                        imported++;
                    }
                    command.Parameters.Clear();
                    applied = Apply(command);
                    transaction.Commit();
                }
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }

            string result = $"Imported assessment procedures for {imported} CCI(s); {applied} CCI-to-control mapping(s) updated" +
                            (skipped > 0 ? $"; {skipped} row(s) without a CCI skipped." : ".");
            LogWriter.LogStatusUpdate(result);
            return result;
        }

        /// <summary>Copies imported procedures onto the CCI-to-control mappings; returns the number of mappings updated.</summary>
        public static int Apply(SQLiteCommand command)
        {
            command.Parameters.Clear();
            command.CommandText = new DdlReader().ReadDdl(
                StoredProcedureBase + "Update.NistControlsCcisFromEmassAssessmentProcedures.dml", Assembly.GetExecutingAssembly());
            return command.ExecuteNonQuery();
        }

        private static bool Is(string cell, string name)
        { return string.Equals((cell ?? string.Empty).Trim(), name, StringComparison.OrdinalIgnoreCase); }

        private static string Cell(string[] row, int index)
        { return index >= 0 && index < row.Length ? row[index] ?? string.Empty : string.Empty; }

        /// <summary>All rows of the first worksheet as text, indexed by column (A = 0).</summary>
        private static List<string[]> ReadRows(string path)
        {
            List<string[]> rows = new List<string[]>();
            using (SpreadsheetDocument document = SpreadsheetDocument.Open(path, false))
            {
                WorkbookPart workbookPart = document.WorkbookPart;
                Sheet sheet = workbookPart.Workbook.Sheets.Elements<Sheet>().First();
                WorksheetPart worksheetPart = (WorksheetPart)workbookPart.GetPartById(sheet.Id);
                SharedStringItem[] sharedStrings = workbookPart.SharedStringTablePart?.SharedStringTable
                    .Elements<SharedStringItem>().ToArray() ?? new SharedStringItem[0];
                foreach (Row row in worksheetPart.Worksheet.Descendants<Row>())
                {
                    List<Cell> cells = row.Elements<Cell>().ToList();
                    int width = cells.Count == 0 ? 0 : cells.Max(c => ColumnIndex(c.CellReference?.Value)) + 1;
                    string[] values = new string[Math.Max(width, cells.Count)];
                    int position = 0;
                    foreach (Cell cell in cells)
                    {
                        int column = cell.CellReference != null ? ColumnIndex(cell.CellReference.Value) : position;
                        position = column + 1;
                        values[column] = CellText(cell, sharedStrings);
                    }
                    rows.Add(values);
                }
            }
            return rows;
        }

        private static string CellText(Cell cell, SharedStringItem[] sharedStrings)
        {
            if (cell.DataType != null && cell.DataType.Value == CellValues.SharedString)
            {
                int index;
                return int.TryParse(cell.CellValue?.Text, out index) && index >= 0 && index < sharedStrings.Length
                    ? sharedStrings[index].InnerText
                    : string.Empty;
            }
            if (cell.DataType != null && cell.DataType.Value == CellValues.InlineString)
            { return cell.InlineString?.InnerText ?? string.Empty; }
            return cell.CellValue?.Text ?? string.Empty;
        }

        private static int ColumnIndex(string reference)
        {
            int index = 0;
            foreach (char c in reference ?? string.Empty)
            {
                if (!char.IsLetter(c))
                { break; }
                index = index * 26 + (char.ToUpperInvariant(c) - 'A' + 1);
            }
            return Math.Max(index - 1, 0);
        }
    }
}
