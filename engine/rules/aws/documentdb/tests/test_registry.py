from engine.rules.registry.documentdb_registry import DOCUMENTDB_RULES


def test_documentdb_registry_contains_all_six_controls():
    rules = DOCUMENTDB_RULES.list_rules()

    assert len(rules) == 6
    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-DOCUMENTDB-001",
        "CS-AWS-DOCUMENTDB-002",
        "CS-AWS-DOCUMENTDB-003",
        "CS-AWS-DOCUMENTDB-004",
        "CS-AWS-DOCUMENTDB-005",
        "CS-AWS-DOCUMENTDB-006",
    ]


def test_documentdb_registry_data_sources_are_valid():
    rules = DOCUMENTDB_RULES.list_rules()

    assert rules[0].data_source == "documentdb_clusters"
    assert rules[1].data_source == "documentdb_clusters"
    assert rules[2].data_source == "documentdb_snapshots"
    assert rules[3].data_source == "documentdb_clusters"
    assert rules[4].data_source == "documentdb_clusters"
    assert rules[5].data_source == "documentdb_clusters"
