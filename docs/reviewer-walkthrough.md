# Reviewer walkthrough

Run `python evaluate.py` and inspect `artifacts/attack_paths.json`.

The example graph has six resources and five relations. The top finding is `public-api -> app-role -> prod-db`, with score `1.0`. The reasons identify a public start, a sensitive destination, and multiple trust transitions. The remediation recommends removing public exposure, constraining the trust edge, and applying least privilege.

The analyzer is read-only and fixture-based. It does not prove exploitability or authenticate to any cloud account.
