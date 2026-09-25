from engine.rules.registry.macie_registry import (
    MACIE_RULES,
)


def test_macie_registry_contains_expected_rules():
    assert len(MACIE_RULES) == 2

    assert [
        rule.rule_id
        for rule in MACIE_RULES.list_rules()
    ] == [
        "CS-AWS-MACIE-001",
        "CS-AWS-MACIE-002",
    ]


def test_macie_rule_data_sources():
    assert (
        MACIE_RULES
        .get_rule("CS-AWS-MACIE-001")
        .data_source
        == "macie_account"
    )

    assert (
        MACIE_RULES
        .get_rule("CS-AWS-MACIE-002")
        .data_source
        == "macie_account"
    )
