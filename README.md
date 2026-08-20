# Cloud Attack-Path and Misconfiguration Prioritization Engine

A read-only graph analyzer for local cloud-configuration fixtures. It models public exposure, identities, trust relationships, network reachability, and sensitive resources, then ranks attack paths using explainable factors.

> **Authorized-use notice:** The analyzer reads local configuration fixtures only. It does not scan, authenticate to, or modify cloud accounts.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python evaluate.py
pytest
```

## Architecture

```text
JSON/Terraform-style fixture -> normalized resources/relations -> directed graph
                                                        |
                                           path search to sensitive assets
                                                        |
                                      explainable score + remediation report
```

## Evaluation plan

The starter fixture includes public and sensitive resources plus trust edges. The next milestone will add secure and vulnerable Terraform fixtures, expected-path labels, parser coverage, path coverage, false-path rate, and sensitivity analysis for asset criticality and exposure.

## Limitations

Cloud providers differ in IAM semantics, network behavior, and resource types. This MVP is provider-neutral and intentionally small. It is a portfolio laboratory, not a replacement for a cloud-native posture-management product.

## Development milestones

The repository history is organized into incremental documentation, implementation, testing, evaluation, and release milestones.
