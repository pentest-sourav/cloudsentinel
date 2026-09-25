from engine.rules.registry.ses_registry import SES_RULES


def test_ses_registry_contains_all_controls():
    rules = SES_RULES.list_rules()

    assert {
        rule.rule_id
        for rule in rules
    } == {
        "CS-AWS-SES-001",
        "CS-AWS-SES-002",
        "CS-AWS-SES-003",
    }


def test_ses_registry_uses_expected_data_sources():
    rules = {
        rule.rule_id: rule
        for rule in SES_RULES.list_rules()
    }

    assert rules["CS-AWS-SES-001"].data_source == (
        "ses_contact_lists"
    )

    assert rules["CS-AWS-SES-002"].data_source == (
        "ses_configuration_sets"
    )

    assert rules["CS-AWS-SES-003"].data_source == (
        "ses_configuration_sets"
    )
