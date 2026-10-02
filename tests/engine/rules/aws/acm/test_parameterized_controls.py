from engine.rules.aws.acm.tagging import check_acm_tagging


def test_acm_required_tags_all_present():
    result = check_acm_tagging(
        "cert-1",
        "arn:aws:acm:region:123:certificate/cert-1",
        [{"Key": "Environment", "Value": "prod"},
         {"Key": "Owner", "Value": "security"}],
        ["Environment", "Owner"],
    )
    assert result is None


def test_acm_required_tags_missing():
    result = check_acm_tagging(
        "cert-1",
        "arn:aws:acm:region:123:certificate/cert-1",
        [{"Key": "Environment", "Value": "prod"}],
        ["Environment", "Owner"],
    )
    assert result is not None
    assert result.missing_tag_keys == ["Owner"]


def test_acm_required_tags_are_case_sensitive():
    result = check_acm_tagging(
        "cert-1",
        "arn:aws:acm:region:123:certificate/cert-1",
        [{"Key": "environment", "Value": "prod"}],
        ["Environment"],
    )
    assert result is not None


def test_acm_system_tags_do_not_satisfy_requirement():
    result = check_acm_tagging(
        "cert-1",
        "arn:aws:acm:region:123:certificate/cert-1",
        [{"Key": "aws:createdBy", "Value": "system"}],
        ["Environment"],
    )
    assert result is not None
