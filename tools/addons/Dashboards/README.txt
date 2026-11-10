Vulnerator 2.0 Dashboards add-on
================================

Offline dashboards inside Vulnerator: open findings by severity, top hosts, compliance by
NIST SP 800-53 Rev 5 control family, POA&M aging, open vs. closed trend, assets with no scan
or checklist, STIG checklists submitted (current or outdated) and active IAVMs.
Nothing is sent anywhere; it needs no server. Free: no license key needed.

Requirements
- Vulnerator 2.0 version 7.4.0 or later (64-bit Windows, .NET Framework 4.8).

Install
- Vulnerator 7.4.0 and later already include it in the "Add-ons" folder: open Dashboards
  in the menu. Settings > Integrations lists it as "License: Free (no license needed)".
- To turn it off, close Vulnerator and move Vulnerator.Dashboards.AddOn.dll out of the
  "Add-ons" folder.
- If you copy the file in yourself from a download, unblock it first: right-click >
  Properties > Unblock, or in PowerShell: Unblock-File .\Vulnerator.Dashboards.AddOn.dll

Notes
- Severity "Very High" (Nessus Critical) and the STIG release each checklist was submitted with
  are recorded by Vulnerator 7.4.0-beta.3 and later. Import older scans and checklists again to
  include them.
- An ACAS finding that the host's newest scan no longer reports is shown as "Unverified". It is
  not counted as open or as closed.
- The trend starts the first day the add-on is used. Its history is kept in the add-on's data
  folder next to the database ("Add-on data\dashboards\trend.json").

Copyright (c) 2026 Hector L. Bones. All rights reserved. See LICENSE.txt.
