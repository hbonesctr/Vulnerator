# Using the Software

The left menu holds the main pages: **Vulnerability Management**, **Configuration Management**, **Reporting** and
**News**, with **Help**, **Settings**, **Theme** and **About** at the bottom.

## Importing files (Vulnerability Management > Ingest)

1. Pick the **File Type**:
   * **Import ACAS** - .nessus files and ACAS CSV exports (Vulnerability Detail List with Plugin ID, Host / IP and
     Severity columns)
   * **Import CKL / CKLB** - STIG checklists from STIG Viewer 2 (.ckl), STIG Viewer 3 (.cklb) and Evaluate-STIG
   * **Import XCCDF** - SCAP Compliance Checker (SCC) and other XCCDF results (.xml)
   * **Import WASSP** - WASSP .html / .xml results
   * **Import Fortify** - Fortify .fpr files
2. Add the files:
   * **Add Files / Zips...** - pick one or more files, or zip files that contain them
   * **Add Folder...** - pick one or more folders; every subfolder and every zip file inside is searched, including
     zips inside zips. A folder of zip files, each holding a .nessus file, is read in one step.
3. Optionally choose an **Ingestion Group** (the system or enclave the files belong to).
4. Select **Execute Ingestion**. The status bar shows progress; the list shows each file's result.

Notes:

* **Evaluate-STIG output:** for checklists, anything under a folder named **Previous** is skipped (Evaluate-STIG keeps
  older results there; the current results are in the **Checklist** folder). A message tells you how many files were
  skipped. To import an older result on purpose, pick that file directly.
* Zip files are extracted to a working folder under your temporary folder; it is cleaned up automatically after a day.
* The same file is only queued once. **Clear List** empties the list.
* A checklist with no host name, FQDN or IP address is imported as a **STIG baseline**: its rules are loaded but no
  findings are recorded. Fill in the asset in STIG Viewer to import it as an assessment.
* Without a STIG library you are asked before checklists or SCAP results are imported (see Getting Started).

## Reviewing findings

* **Findings** - every finding with its host, status, raw / residual risk and mitigation; filter, edit and approve here.
* **Group Mitigations** - mitigations shared by every finding of a vulnerability within a group.
* **CCI Mapping** - the CCIs and NIST SP 800-53 Rev 5 controls (with DoD assessment procedures) mapped to each
  vulnerability; adjust the mapping when needed.

## Configuration Management

The hardware, software and groups found in the imported files. From **Hardware** you can export a STIG checklist (.ckl)
for a host, built from the STIG library and that host's findings.

## Reporting

Choose the report, the filters (finding type, severity, status, group) and export:

* **eMASS POA&M** - the eMASS POA&M import workbook, with Rev 5 controls and assessment procedures
* **eMASS Hardware / Software** - the eMASS hardware and software list workbooks
* The other Excel reports (for example the Risk Assessment Report and the STIG / ACAS details)

Before each export you can accept or change the **marking**; it is printed in the header and footer of every sheet and
stored in the file properties. Turn the question off in Settings if you always use the same marking.
