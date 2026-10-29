# NIST SP 800-53 Rev 5 reference data

Vulnerator embeds its control and CCI reference data from `Resources/RawData`. These scripts regenerate and verify it.

| File in `Resources/RawData` | What it holds | Source |
| --- | --- | --- |
| `U_CCI_List.xml` | CCI definitions, status and references | DISA CCI list (currently version 2022-03-09) |
| `NIST_800-53r5_Controls.xml` | 1,014 active Rev 5 controls and enhancements: title, statement, discussion, Low/Moderate/High flags | NIST OSCAL SP 800-53 Rev 5 catalog (5.2.0) and SP 800-53B baselines |
| `NIST_800-53r5_CCI_Mapping.xml` | 3,813 CCI-to-control pairs | Rev 5 references in the DISA CCI list |
| `NIST_800-53r5_MonitoringFrequency.xml` | Monitoring frequency | Carried forward from the Rev 4 data for controls that still exist |

`rev4-source/` keeps the retired Rev 4 files. The generator reads them to carry DoD implementation guidance and assessment procedure text forward by CCI, and monitoring frequency by control.

## Updating to a newer DISA CCI list

1. Download the current CCI list from DISA (public.cyber.mil, "Control Correlation Identifier") and extract `U_CCI_List.xml`.
2. Get the NIST OSCAL Rev 5 files from https://github.com/usnistgov/oscal-content under `nist.gov/SP800-53/rev5/json/`: the catalog plus the LOW, MODERATE and HIGH baseline resolved-profile catalogs.
3. Run, from this folder:

   ```
   python build_reference_data.py --cci U_CCI_List.xml \
     --catalog NIST_SP-800-53_rev5_catalog.json \
     --low NIST_SP-800-53_rev5_LOW-baseline-resolved-profile_catalog.json \
     --moderate NIST_SP-800-53_rev5_MODERATE-baseline-resolved-profile_catalog.json \
     --high NIST_SP-800-53_rev5_HIGH-baseline-resolved-profile_catalog.json \
     --rev4-cci-mapping rev4-source/NIST_800-53_CCI_Mapping.xml \
     --rev4-frequency rev4-source/NIST_800-53_MonitoringFrequency_Mapping.xml \
     --out ../../Resources/RawData
   ```

4. Raise `ReferenceDataVersion` in `Model/DataAccess/DatabaseBuilder.cs` by one, so existing databases reload the data on next launch.
5. Run `python verify_reference_data.py ../..` and commit. The GitHub Actions build runs the same check on every push.

## Known limits

- **Baseline flags** come from NIST SP 800-53B (one Low/Moderate/High baseline per control), applied equally to confidentiality, integrity and availability. They are not CNSSI 1253 per-objective values. If you can supply the CNSSI 1253 appendix tables, the generator can be extended to use them.
- **DoD guidance and assessment procedure text** exists only for CCIs that were in the Rev 4 data (2,263 of 3,813 pairs). CCIs added for Rev 5 have empty guidance.
- **SI-7(13)** is referenced by CCI-002734 but withdrawn in Rev 5 (incorporated into CM-14), so that one reference is skipped.
