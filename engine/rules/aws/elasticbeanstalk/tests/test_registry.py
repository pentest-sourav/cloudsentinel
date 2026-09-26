from engine.rules.registry.elasticbeanstalk_registry import (
    ELASTICBEANSTALK_RULES,
)


def test_elasticbeanstalk_registry_contains_all_controls():
    rule_ids = {
        rule.rule_id
        for rule in ELASTICBEANSTALK_RULES.rules
    }

    assert rule_ids == {
        "CS-AWS-ELASTICBEANSTALK-001",
        "CS-AWS-ELASTICBEANSTALK-002",
        "CS-AWS-ELASTICBEANSTALK-003",
    }


def test_elasticbeanstalk_registry_uses_environment_data_source():
    for rule in ELASTICBEANSTALK_RULES.rules:
        assert (
            rule.data_source
            == "elasticbeanstalk_environments"
        )
        assert rule.collection_mode == "multiple"
