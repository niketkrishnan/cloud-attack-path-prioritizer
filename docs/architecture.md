# Architecture

```text
secure and vulnerable local cloud-configuration fixtures with expected path behavior -> normalized input -> security analysis -> explainable result
                                                |
                                         tests and evaluation
```

The repository keeps the core analysis logic independent from the command-line
evaluation entry point. This supports deterministic unit tests and makes it
possible to add an API or dashboard without changing the security boundary.


## Publication hardening

The analyzer ignores relationships that reference resources absent from the local fixture and exposes those references as deterministic validation warnings. Analyst-facing summaries report only finding counts and bounded priority statistics; raw cloud records remain outside the output contract.
