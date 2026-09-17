from engine.rules.registry.iam_handlers import IAM_DATA_SOURCE_HANDLERS


def test_iam_data_source_handlers_have_required_sources():
    assert set(IAM_DATA_SOURCE_HANDLERS.keys()) == {
        "root_mfa",
        "iam_users",
    }


def test_iam_data_source_handlers_are_callable():
    for handler in IAM_DATA_SOURCE_HANDLERS.values():
        assert callable(handler)
