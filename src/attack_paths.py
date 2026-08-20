"""Read-only cloud attack-path analysis over local configuration fixtures."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

import networkx as nx


@dataclass(frozen=True)
class Resource:
    resource_id: str
    kind: str
    criticality: float
    public: bool = False
    sensitive: bool = False


@dataclass(frozen=True)
class Relation:
    source: str
    target: str
    relation: str
    weight: float = 1.0


@dataclass(frozen=True)
class PathFinding:
    path: tuple[str, ...]
    score: float
    reasons: tuple[str, ...]
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["path"] = list(self.path)
        result["reasons"] = list(self.reasons)
        return result


class CloudAttackPathAnalyzer:
    def __init__(self, resources: list[Resource], relations: list[Relation]) -> None:
        self.resources = {item.resource_id: item for item in resources}
        self.graph = nx.DiGraph()
        self.validation_warnings: list[str] = []
        for resource in resources:
            self.graph.add_node(resource.resource_id, **asdict(resource))
        for relation in relations:
            if relation.source not in self.resources or relation.target not in self.resources:
                self.validation_warnings.append(
                    f"ignored relation with unknown resource: {relation.source}->{relation.target}"
                )
                continue
            self.graph.add_edge(relation.source, relation.target, relation=relation.relation, weight=relation.weight)

    def graph_warnings(self) -> tuple[str, ...]:
        """Return deterministic, non-sensitive fixture validation warnings."""
        return tuple(self.validation_warnings)

    def find_paths(self, start_kinds: set[str] | None = None, max_hops: int = 6) -> list[PathFinding]:
        starts = [rid for rid, res in self.resources.items() if res.public or (start_kinds and res.kind in start_kinds)]
        targets = [rid for rid, res in self.resources.items() if res.sensitive]
        findings: list[PathFinding] = []
        for start in starts:
            for target in targets:
                if start == target or not nx.has_path(self.graph, start, target):
                    continue
                for path in nx.all_simple_paths(self.graph, start, target, cutoff=max_hops):
                    reasons: list[str] = []
                    score = 0.0
                    if self.resources[start].public:
                        reasons.append("path starts at a public resource")
                        score += 0.25
                    if self.resources[target].sensitive:
                        reasons.append("path reaches a sensitive resource")
                        score += 0.35
                    privilege_edges = 0
                    for left, right in zip(path, path[1:]):
                        relation = self.graph.edges[left, right]["relation"]
                        if relation in {"assumes", "can_read", "can_admin", "network_reaches"}:
                            privilege_edges += 1
                    if privilege_edges >= 2:
                        reasons.append("multiple trust or privilege transitions")
                        score += 0.25
                    score += min(self.resources[target].criticality * 0.15, 0.15)
                    findings.append(
                        PathFinding(
                            path=tuple(path),
                            score=round(min(score, 1.0), 4),
                            reasons=tuple(reasons),
                            remediation="Remove public exposure, constrain the trust edge, and apply least privilege to the identity on this path.",
                        )
                    )
        return sorted(findings, key=lambda item: item.score, reverse=True)


def summarize_findings(findings: list[PathFinding]) -> dict[str, Any]:
    """Return a compact analyst summary without exposing raw cloud records."""
    scores = [finding.score for finding in findings]
    return {
        "finding_count": len(findings),
        "high_priority_count": sum(score >= 0.7 for score in scores),
        "top_score": max(scores, default=0.0),
    }


def load_fixture(payload: dict[str, Any]) -> CloudAttackPathAnalyzer:
    resources = [Resource(**item) for item in payload["resources"]]
    relations = [Relation(**item) for item in payload["relations"]]
    return CloudAttackPathAnalyzer(resources, relations)


def summarize_resource_exposure(analyzer: CloudAttackPathAnalyzer) -> dict[str, int]:
    """Return deterministic fixture coverage metrics for analyst reports."""
    return {
        "resource_count": len(analyzer.resources),
        "relation_count": analyzer.graph.number_of_edges(),
        "public_resource_count": sum(resource.public for resource in analyzer.resources.values()),
        "sensitive_resource_count": sum(resource.sensitive for resource in analyzer.resources.values()),
        "validation_warning_count": len(analyzer.graph_warnings()),
    }
