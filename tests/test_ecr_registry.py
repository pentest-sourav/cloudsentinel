from engine.rules.registry.ecr_registry import ECR_RULES


def test_ecr_registry_contains_five_rules():
    rules = list(ECR_RULES)

    assert len(rules) == 5
    assert [rule.rule_id for rule in rules] == [
        "CS-AWS-ECR-005",
        "CS-AWS-ECR-001",
        "CS-AWS-ECR-002",
        "CS-AWS-ECR-003",
        "CS-AWS-ECR-004",
    ]
