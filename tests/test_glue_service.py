from unittest.mock import Mock

import pytest

from scanner.aws.services.glue import GlueService


def test_list_jobs_uses_paginator():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {"Jobs": [{"Name": "job-1"}]},
        {"Jobs": [{"Name": "job-2"}]},
    ]

    client.get_paginator.return_value = paginator

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.glue.create_aws_client",
            Mock(return_value=client),
        )

        service = GlueService(session)
        result = service.list_jobs()

    assert result == [
        {"Name": "job-1"},
        {"Name": "job-2"},
    ]

    client.get_paginator.assert_called_once_with(
        "get_jobs"
    )


def test_get_tags_returns_tags():
    session = Mock()
    client = Mock()

    client.get_tags.return_value = {
        "Tags": {
            "Environment": "prod",
        }
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.glue.create_aws_client",
            Mock(return_value=client),
        )

        service = GlueService(session)
        result = service.get_tags(
            "arn:aws:glue:ap-south-1:123456789012:job/test"
        )

    assert result == {"Environment": "prod"}


def test_get_tags_empty_arn_is_safe():
    session = Mock()
    client = Mock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.glue.create_aws_client",
            Mock(return_value=client),
        )

        service = GlueService(session)
        assert service.get_tags("") == {}

    client.get_tags.assert_not_called()


def test_list_ml_transforms_uses_paginator():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {"Transforms": [{"TransformId": "t-1"}]},
        {"Transforms": [{"TransformId": "t-2"}]},
    ]

    client.get_paginator.return_value = paginator

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.glue.create_aws_client",
            Mock(return_value=client),
        )

        service = GlueService(session)
        result = service.list_ml_transforms()

    assert result == [
        {"TransformId": "t-1"},
        {"TransformId": "t-2"},
    ]

    client.get_paginator.assert_called_once_with(
        "get_ml_transforms"
    )
