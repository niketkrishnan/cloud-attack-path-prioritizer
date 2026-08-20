# Reviewer Guide

## Five-minute path

1. Run `python evaluate.py` and inspect ranked paths and summary metrics.
2. Trace resource and relation normalization into the directed graph.
3. Review tests for public-to-sensitive reachability, disconnected assets, dangling references, and deterministic exposure metrics.
4. Discuss provider-neutral limitations and least-privilege remediation.

## Evidence of engineering judgment

The tool is read-only, validates uncertain relationships, and exposes the score drivers instead of presenting a black-box priority.
