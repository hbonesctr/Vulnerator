<div align="center">
    <img width="25%" src="Vulnerator_Logo_Large_Color_SquareBackground_20190805.png">
    <h1>Vulnerator 2.0</h1>
    <h3>Vulnerability continuous monitoring for DoD RMF</h3>
</div>

Vulnerator 2.0 is a maintained fork of [Vulnerator](https://github.com/Vulnerator/Vulnerator). It brings the tool to
NIST SP 800-53 Rev 5, current DISA checklist and scan formats, and eMASS POA&M and hardware / software exports, and it
runs offline on closed networks without administrator rights.

### What it does
- Imports STIG checklists (.ckl, STIG Viewer 3 .cklb), ACAS / Nessus scans (.nessus, CSV), SCAP / SCC XCCDF results and
  the DISA STIG library.
- Maps findings to CCIs and NIST SP 800-53 Rev 5 controls (DISA CCI list, CNSSI 1253 baselines), with eMASS assessment
  procedures from your own IG/AP export.
- Exports eMASS POA&M and hardware / software workbooks, a Risk Assessment Report, and per-host STIG checklists.

### Getting started
1. Download the zip from [Releases](https://github.com/hbonesctr/Vulnerator/releases) and check its SHA-256 against
   the release page (`Get-FileHash .\Vulnerator-<version>.zip`).
2. Extract the whole folder and run `Vulnerator.exe` from inside it (.NET Framework 4.8; no installation, no
   administrator rights).
3. Choose **Portable** (database next to the program) or **Persistent** (a database file you pick).
4. Optional: Settings > STIG library (the DISA quarterly zip) and Settings > Import assessment procedures (your eMASS
   IG/AP export).

Before relying on a build, run `Test-RealData.ps1` (in the release folder) against a folder of your own files; it uses a
throwaway database and sends nothing anywhere. Release notes are in [docs/release-notes](docs/release-notes).

### Building
Builds and tests run in GitHub Actions on Windows (`.github/workflows/build.yml`): reference-data checks, SQL compile
checks, the Release build, end-to-end import / export tests on synthetic files, and eMASS template checks. Pushing a
`v*` tag, or a `release/v*` branch, publishes a release with the built zip and its SHA-256. Reference data is regenerated with the scripts in
[tools/rev5](tools/rev5).

### Credits and license
Based on Vulnerator by Alex Kuchta and contributors. MIT License (see [LICENSE](LICENSE)).
