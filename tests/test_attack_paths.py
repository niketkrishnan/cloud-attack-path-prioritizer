from attack_paths import CloudAttackPathAnalyzer, Relation, Resource, summarize_findings


def test_finds_public_to_sensitive_path():
    resources = [
        Resource("public", "load_balancer", 0.5, public=True),
        Resource("role", "role", 0.5),
        Resource("db", "database", 1.0, sensitive=True),
    ]
    relations = [
        Relation("public", "role", "network_reaches"),
        Relation("role", "db", "can_admin"),
    ]
    findings = CloudAttackPathAnalyzer(resources, relations).find_paths()
    assert findings
    assert findings[0].path == ("public", "role", "db")
    assert findings[0].score > 0.5
    assert "sensitive resource" in " ".join(findings[0].reasons)


def test_ignores_unconnected_sensitive_resource():
    resources = [
        Resource("public", "load_balancer", 0.5, public=True),
        Resource("db", "database", 1.0, sensitive=True),
    ]
    findings = CloudAttackPathAnalyzer(resources, []).find_paths()
    assert findings == []


def test_dangling_relations_are_reported_and_ignored():
    analyzer = CloudAttackPathAnalyzer(
        [Resource("public-api", "service", 0.4, public=True)],
        [Relation("public-api", "missing-db", "network_reaches")],
    )
    assert analyzer.graph_warnings() == (
        "ignored relation with unknown resource: public-api->missing-db",
    )
    assert analyzer.find_paths() == []


def test_finding_summary_is_bounded_and_explainable():
    findings = CloudAttackPathAnalyzer(
        [
            Resource("public-api", "service", 0.4, public=True),
            Resource("db", "database", 1.0, sensitive=True),
        ],
        [Relation("public-api", "db", "network_reaches")],
    ).find_paths()
    assert summarize_findings(findings) == {
        "finding_count": 1,
        "high_priority_count": 1,
        "top_score": findings[0].score,
    }
