from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.appflow import AppFlowService


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"

    client = Mock()

    service = AppFlowService(session)
    service.appflow_client = client

    return service, client


def test_list_flows_collects_paginated_results():
    service, client = make_service()

    client.list_flows.side_effect = [
        {
            "flows": [
                {
                    "flowName": "flow_one",
                    "flowArn": (
                        "arn:aws:appflow:ap-south-1:"
                        "123456789012:flow/flow_one"
                    ),
                }
            ],
            "nextToken": "token-1",
        },
        {
            "flows": [
                {
                    "flowName": "flow_two",
                    "flowArn": (
                        "arn:aws:appflow:ap-south-1:"
                        "123456789012:flow/flow_two"
                    ),
                }
            ],
        },
    ]

    assert service.list_flows() == [
        {
            "flowName": "flow_one",
            "flowArn": (
                "arn:aws:appflow:ap-south-1:"
                "123456789012:flow/flow_one"
            ),
        },
        {
            "flowName": "flow_two",
            "flowArn": (
                "arn:aws:appflow:ap-south-1:"
                "123456789012:flow/flow_two"
            ),
        },
    ]

    assert client.list_flows.call_args_list == [
        (( ), {"maxResults": 100}),
        (( ), {"maxResults": 100, "nextToken": "token-1"}),
    ]


def test_list_tags_for_resource_returns_tags():
    service, client = make_service()

    client.list_tags_for_resource.return_value = {
        "tags": {
            "Environment": "prod",
            "Owner": "security",
        }
    }

    assert service.list_tags_for_resource(
        "arn:flow"
    ) == {
        "Environment": "prod",
        "Owner": "security",
    }

    client.list_tags_for_resource.assert_called_once_with(
        resourceArn="arn:flow"
    )


def test_list_tags_for_resource_returns_empty_for_invalid_arn():
    service, client = make_service()

    assert service.list_tags_for_resource("") == {}

    client.list_tags_for_resource.assert_not_called()


def test_list_flows_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListFlows",
    )

    client.list_flows.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_flows()
