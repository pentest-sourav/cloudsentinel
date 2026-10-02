from unittest.mock import Mock, call

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.batch import BatchService


def _client_error(
    code="AccessDeniedException",
):
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": "denied",
            }
        },
        "DescribeJobQueues",
    )


def test_describe_job_queues_paginates():
    session = Mock()
    client = Mock()

    client.describe_job_queues.side_effect = [
        {
            "jobQueues": [
                {
                    "jobQueueArn": "arn:queue1",
                }
            ],
            "nextToken": "page-2",
        },
        {
            "jobQueues": [
                {
                    "jobQueueArn": "arn:queue2",
                }
            ],
        },
    ]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.describe_job_queues() == [
        {
            "jobQueueArn": "arn:queue1",
        },
        {
            "jobQueueArn": "arn:queue2",
        },
    ]

    assert client.describe_job_queues.call_args_list == [
        call(maxResults=100),
        call(
            maxResults=100,
            nextToken="page-2",
        ),
    ]


def test_list_scheduling_policies_uses_paginator():
    session = Mock()
    client = Mock()
    paginator = Mock()

    paginator.paginate.return_value = [
        {
            "schedulingPolicies": [
                {
                    "arn": "arn:policy",
                }
            ]
        },
        {
            "schedulingPolicies": [
                {
                    "arn": "arn:policy2",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.list_scheduling_policies() == [
        {
            "arn": "arn:policy",
        },
        {
            "arn": "arn:policy2",
        },
    ]

    client.get_paginator.assert_called_once_with(
        "list_scheduling_policies"
    )


def test_describe_scheduling_policies():
    session = Mock()
    client = Mock()

    client.describe_scheduling_policies.return_value = {
        "schedulingPolicies": [
            {
                "arn": "arn:policy",
                "name": "policy",
            }
        ]
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.describe_scheduling_policies(
        ["arn:policy"]
    ) == [
        {
            "arn": "arn:policy",
            "name": "policy",
        }
    ]

    client.describe_scheduling_policies.assert_called_once_with(
        arns=["arn:policy"]
    )


def test_describe_compute_environments_paginates():
    session = Mock()
    client = Mock()

    client.describe_compute_environments.side_effect = [
        {
            "computeEnvironments": [
                {
                    "computeEnvironmentArn": "arn:env1",
                }
            ],
            "nextToken": "page-2",
        },
        {
            "computeEnvironments": [
                {
                    "computeEnvironmentArn": "arn:env2",
                }
            ],
        },
    ]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.describe_compute_environments() == [
        {
            "computeEnvironmentArn": "arn:env1",
        },
        {
            "computeEnvironmentArn": "arn:env2",
        },
    ]

    assert client.describe_compute_environments.call_args_list == [
        call(maxResults=100),
        call(
            maxResults=100,
            nextToken="page-2",
        ),
    ]


def test_describe_job_queues_stops_on_repeated_next_token():
    session = Mock()
    client = Mock()

    client.describe_job_queues.side_effect = [
        {
            "jobQueues": [
                {
                    "jobQueueArn": "arn:queue",
                }
            ],
            "nextToken": "same-token",
        },
        {
            "jobQueues": [
                {
                    "jobQueueArn": "arn:queue2",
                }
            ],
            "nextToken": "same-token",
        },
    ]

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.describe_job_queues() == [
        {
            "jobQueueArn": "arn:queue",
        },
        {
            "jobQueueArn": "arn:queue2",
        },
    ]

    assert client.describe_job_queues.call_count == 2


def test_list_tags_for_resource():
    session = Mock()
    client = Mock()

    client.list_tags_for_resource.return_value = {
        "tags": {
            "Environment": "prod",
        }
    }

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.list_tags_for_resource(
        "arn:resource"
    ) == {
        "Environment": "prod",
    }


def test_invalid_tag_arn_returns_empty_tags():
    session = Mock()
    client = Mock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    assert service.list_tags_for_resource("") == {}

    client.list_tags_for_resource.assert_not_called()


def test_client_error_is_normalized():
    session = Mock()
    client = Mock()

    client.describe_job_queues.side_effect = (
        _client_error()
    )

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "scanner.aws.services.batch.create_aws_client",
            lambda *_: client,
        )

        service = BatchService(session)

    with pytest.raises(
        RuntimeError,
        match="AWS Batch describe_job_queues failed",
    ):
        service.describe_job_queues()
