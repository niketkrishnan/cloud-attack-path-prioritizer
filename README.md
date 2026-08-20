# Cloud Attack-Path and Misconfiguration Prioritization Engine

[![CI](https://github.com/niketkrishnan/cloud-attack-path-prioritizer/actions/workflows/ci.yml/badge.svg)](https://github.com/niketkrishnan/cloud-attack-path-prioritizer/actions/workflows/ci.yml)

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


## Reviewer quickstart

Run `python evaluate.py`, inspect `artifacts/attack_paths.json`, and read `src/attack_paths.py` alongside `tests/test_attack_paths.py`. Reviewers can trace each ranked path to public exposure, sensitive-resource reachability, privilege transitions, criticality, and remediation text.

## What I learned

A cloud misconfiguration becomes more actionable when it is connected to a reachable sensitive asset. Graph analysis makes that relationship visible, while validation warnings and bounded summaries keep uncertain fixture data from being mistaken for provider truth.

## Limitations

The analyzer is provider-neutral and reads only local fixtures. It does not authenticate to clouds, infer every IAM semantic, or prove exploitability. Production use would require provider-specific parsers, asset inventory freshness, authorization review, and calibrated risk validation.
