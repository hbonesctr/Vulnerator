#!/usr/bin/env python3
"""
Checks the STIG Details workbook and the PDF Summary produced by Test-ChecklistImport.ps1 from the synthetic files.
Usage: python verify_summary_reports.py <sample-STIG-Details.xlsx> <sample-PDF-Summary.pdf>
"""
import re
import sys

import openpyxl
from pypdf import PdfReader

DETAIL_HEADERS = [
    "STIG Name", "STIG Version", "Host Name", "IP Address", "Group(s)", "Vuln ID", "Rule ID", "STIG ID",
    "Rule Title", "Severity", "Severity Override", "Status", "Mitigated Status", "NIST SP 800-53 Rev 5 Controls",
    "CCIs", "Discussion", "Check Content", "Fix Text", "Finding Details", "Comments", "Finding Type",
    "Source File", "Last Observed",
]
SUMMARY_HEADERS = [
    "STIG Name", "STIG Version", "Hosts", "Rules Evaluated", "Open CAT I", "Open CAT II", "Open CAT III",
    "Not a Finding", "Not Applicable", "Not Reviewed", "Compliance %",
]
STATUSES = {"Open", "Not a Finding", "Not Applicable", "Not Reviewed", "Error"}
failures = []


def check(condition, message):
    print(("PASS " if condition else "FAIL ") + message)
    if not condition:
        failures.append(message)


def main(xlsx_path, pdf_path):
    book = openpyxl.load_workbook(xlsx_path)
    check(book.sheetnames == ["STIG Details", "Summary by STIG"], "STIG Details sheets: %s" % book.sheetnames)
    details = book["STIG Details"]
    headers = [c.value for c in details[1]]
    check(headers == DETAIL_HEADERS, "STIG Details headers")
    rows = [r for r in details.iter_rows(min_row=2, values_only=True) if any(v is not None for v in r)]
    check(len(rows) >= 3, "STIG Details has rows (%d)" % len(rows))
    col = {h: i for i, h in enumerate(DETAIL_HEADERS)}
    check(all(r[col["Status"]] in STATUSES for r in rows), "every status is a checklist status")
    check(all((r[col["Severity"]] or "").startswith("CAT ") for r in rows), "every severity is CAT I/II/III")
    ckl_rules = [r[col["Rule ID"]] for r in rows if r[col["Finding Type"]] == "CKL"]
    check(ckl_rules and all(re.match(r"^SV-\d+r\d+_rule$", v or "") for v in ckl_rules), "checklist Rule IDs are SV-...r#_rule")
    check(any(r[col["NIST SP 800-53 Rev 5 Controls"]] for r in rows), "rows carry NIST controls")
    check(details.freeze_panes == "A2", "header row frozen (%s)" % details.freeze_panes)
    check(details.auto_filter.ref is not None and details.auto_filter.ref.startswith("A1:W"), "filter buttons on the header")
    summary = book["Summary by STIG"]
    check([c.value for c in summary[1]] == SUMMARY_HEADERS, "Summary by STIG headers")
    summary_rows = [r for r in summary.iter_rows(min_row=2, values_only=True) if r[0] is not None]
    evaluated = sum(int(r[3]) for r in summary_rows)
    check(evaluated == len(rows), "summary 'Rules Evaluated' adds up to the detail rows (%d vs %d)" % (evaluated, len(rows)))

    reader = PdfReader(pdf_path)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    check(len(reader.pages) >= 1, "PDF has %d page(s)" % len(reader.pages))
    for expected in ["Vulnerability Summary", "Overview", "Open findings by source and severity", "Results by status",
                     "STIG compliance", "CUI//TEST MARKING", "Vulnerator 2.0"]:
        check(expected in text, "PDF contains '%s'" % expected)

    if failures:
        print("%d check(s) failed" % len(failures))
        sys.exit(1)
    print("Summary reports verified.")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
