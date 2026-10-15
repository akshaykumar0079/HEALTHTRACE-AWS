# Provenance of the four tracked dataset files

Question from the M1 review: where did the tracked dataset files come from, and are they safe to keep?
This note is based only on Git history, file metadata and existing documentation. Patient-level rows were
not opened or reproduced. Files were not modified, moved, deleted or redistributed.

| File | Added by (Git author) | Commit | Date | Self-description |
|---|---|---|---|---|
| `cancer_patients_40_sample.csv` | Magesh S | d26b7b8 "Add files via upload" | 2026-09-28 | none inside the file or in the repository docs |
| `covid19_patient_risk_top50.csv` | Nimal R.S | 7f0a061 "Add files via upload" | 2026-09-28 | none |
| `medical_dataset_40_patients_hackathon.xlsx` | Akshay kumar S | b24ae03 "Add files via upload" | 2026-09-28 | `Dataset_Notes` sheet: "All patient data in this workbook is synthetic ... No real patient identifiers or clinical records" |
| `synthetic_medical_patient_dataset.xlsx` | Akshay kumar S | b24ae03 "Add files via upload" | 2026-09-28 | `Dataset_Notes` sheet: "Synthetic / de-identified ... Testing and demonstration only" |

## What is established
* All four were uploaded through the web UI on the same day by three different contributors; no commit message,
  README, or docs page mentions them, and no code under `backend/`, `frontend/` or `scripts/` reads them.
* Both workbooks were generated with `openpyxl` and say, in their own notes sheet, that they are synthetic.
  That is the creators' statement; it was not independently verified.

## What is not established
* **The two CSVs have no stated origin.** Header names only (no rows were read):
  * `covid19_patient_risk_top50.csv` has a 38-column clinical schema (USMER, MEDICAL_UNIT, DATE_DIED,
    CLASIFFICATION_FINAL, ...) whose names and misspelling match a widely circulated public COVID-19
    patient dataset. It may be a sample of a real public-health extract with derived columns added.
    I could not confirm that or its licence from the repository.
  * `cancer_patients_40_sample.csv` has 15 columns (Patient_ID, Country_Region, Cancer_Type, ...) that look like a
    synthetic/public-teaching dataset. Origin unconfirmed.
* Whether any file contains real or re-identifiable patient data cannot be settled from metadata.

## Recommendation (decision is yours)
1. Ask the three contributors where each file came from and under what licence or terms.
2. Until answered, treat the two CSVs as **unverified**: do not ship them in a hospital pilot, release archive or
   public deployment, and do not use them as a demo of real data.
3. If the answer is "real or unknown", remove them from the repository **and its history** by a deliberate,
   reviewed step of your own (this milestone did not touch them).
4. If synthetic, add a one-line origin note (and licence) next to them so the question does not recur.

All three commits are already contained in `origin/main` (as last fetched), i.e. they are on the GitHub remote. I did not check the
repository's visibility; if it is public, the files have been exposed already and rewriting history would not undo that.
