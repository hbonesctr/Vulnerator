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
* **Ports, protocols and services** are collected from every ACAS / Nessus import while *Parse ACAS vulnerability port
  information* is on (the default). Credentialed scans give the fullest list (netstat plugins 14272 / 34220); UDP
  services appear only when the scan covered UDP. Nessus marks guessed service names with "?". Review and name them
  under Configuration Management > Ports, Protocols, Services.
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
* **Risk Assessment Report** - risk workbook of the findings by status and risk level
* **SCAP & STIG Discrepancies** - rules where the SCAP result and the checklist disagree for the same host
* **STIG Details** - every checklist and SCAP rule result, one row per host and rule, with the rule text (discussion,
  check, fix), finding details, comments, Rev 5 controls and CCIs; filter buttons on every column and a
  *Summary by STIG* sheet (hosts, open CAT I / II / III, compliance %)
* **Ports, Protocols & Services** - the ports, protocols and services ACAS / Nessus scans observed, one row per
  port / protocol / service with its hosts, IP addresses, groups and the Nessus plugins that showed it, plus a *By Host*
  sheet; a starting point for the PPSM registration (only the group filter applies)
* **PDF Summary** - a printable overview: totals, open findings by source and severity, results by status, STIG
  compliance, the assets with the most open findings and the most widespread open findings

Each report has its own filters; tick **Use Global Value** to use the Global ones. Generate one report with its button,
or tick several and use **Launch Selected Reports** to save them all to one folder.

Before each export you can accept or change the **marking**; it is printed in the header and footer of every sheet and
stored in the file properties (for the PDF, at the top and bottom of every page). Turn the question off in Settings if you always use the same marking.

## Add-ons
Add-ons are optional extensions (for example dashboards or integrations); none come with Vulnerator. To install one,
put its files in the **Add-ons** folder next to Vulnerator.exe (the main file ends in `.AddOn.dll`) and restart
Vulnerator. Its pages appear in the menu and its options under **Settings > Integrations**, which also lists every
add-on found and whether it loaded. An add-on that cannot load is skipped and the reason is logged; Vulnerator keeps
working. If Windows marks the files as downloaded, right-click them, choose **Properties**, tick **Unblock** and restart.
Add-ons can read findings, hardware, the STIG releases submitted and the eMASS POA&M items, but cannot change the database.

### Add-on licenses
Some add-ons need a license. Under **Settings > Integrations > Licenses**, paste the key and choose **Add license**,
or choose **Import .lic file...**. Each add-on shows its license status (for example the expiry date) and what it says
about each license entered. Licenses are kept in an **Add-on licenses** folder next to the database and are checked on
this computer only; nothing is sent anywhere. **Remove** deletes a license from this computer.
