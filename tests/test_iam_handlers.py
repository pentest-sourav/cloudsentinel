from engine.rules.registry.iam_handlers import IAM_DATA_SOURCE_HANDLERS


def test_iam_data_source_handlers_have_required_sources():
    assert set(IAM_DATA_SOURCE_HANDLERS.keys()) == {
        "root_mfa",
        "iam_users",
        "iam_access_keys",
        "password_policy",
        "credential_report",
        "broad_user_policies",
        "broad_group_policies",
        "broad_user_inline_policies",
    }
