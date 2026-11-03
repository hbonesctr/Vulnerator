# Vulnerator 2.0

Vulnerator 2.0 consolidates vulnerability and STIG compliance data for DoD Risk Management Framework (RMF) work and
produces eMASS-ready outputs. It is a maintained rewrite of the original Vulnerator, updated for NIST SP 800-53 Rev 5,
current DISA checklist and scan formats, and closed networks.

## What it does

* Imports STIG checklists (.ckl and STIG Viewer 3 .cklb), including zip files and Evaluate-STIG output folders
* Imports ACAS / Nessus scans (.nessus and CSV), including folders of zip files
* Imports SCAP / SCC XCCDF results and the DISA STIG library
* Maps findings to CCIs and NIST SP 800-53 Rev 5 controls, with eMASS assessment procedures from your own IG/AP export
* Exports the eMASS POA&M, the eMASS hardware / software list, reports, and per-host STIG checklists, each with the
  classification / handling marking you confirm

## Where to start

1. **Getting Started** - first launch, database choice and one-time setup
2. **Using the Software** - importing files, reviewing findings and exporting
3. **Error Reporting** - where the log is and what to send when something fails

Vulnerator runs offline. It only contacts GitHub when "Online checks" is turned on in Settings.
