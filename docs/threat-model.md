# Threat Model

## Protected capability

This project addresses read-only cloud graph analysis, public exposure, trust relationships, privilege transitions, and explainable remediation ranking.

## In-scope threats

The main in-scope threats are public-to-sensitive paths, excessive permissions, weak trust boundaries, and unintended resource reachability.

## Trust boundaries

Inputs are untrusted telemetry, configuration, dependency metadata, identity
events, or application text depending on the project. The analysis layer is
read-only in demo mode. No external system is scanned or modified.

## Out of scope

Production access, credential collection, unrestricted tool execution, active
exploitation, and unauthorized data collection are out of scope.
