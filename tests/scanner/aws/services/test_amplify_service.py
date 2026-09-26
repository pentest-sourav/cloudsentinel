from unittest.mock import Mock

import pytest
from botocore.exceptions import ClientError

from scanner.aws.services.amplify import (
    AmplifyService,
)


def make_service():
    session = Mock()
    session.region_name = "ap-south-1"

    client = Mock()

    service = AmplifyService(session)
    service.amplify_client = client

    return service, client


def test_list_apps_collects_paginated_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "apps": [
                {
                    "appId": "d111",
                    "appArn": "arn:app:one",
                    "name": "one",
                }
            ]
        },
        {
            "apps": [
                {
                    "appId": "d222",
                    "appArn": "arn:app:two",
                    "name": "two",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_apps() == [
        {
            "appId": "d111",
            "appArn": "arn:app:one",
            "name": "one",
        },
        {
            "appId": "d222",
            "appArn": "arn:app:two",
            "name": "two",
        },
    ]

    client.get_paginator.assert_called_once_with(
        "list_apps"
    )


def test_list_apps_ignores_non_dict_entries():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "apps": [
                {"appId": "d111"},
                None,
                "invalid",
            ]
        }
    ]

    client.get_paginator.return_value = paginator

    assert service.list_apps() == [
        {"appId": "d111"},
    ]


def test_list_branches_passes_app_id_and_collects_results():
    service, client = make_service()

    paginator = Mock()
    paginator.paginate.return_value = [
        {
            "branches": [
                {
                    "branchArn": "arn:branch:one",
                    "branchName": "main",
                }
            ]
        },
        {
            "branches": [
                {
                    "branchArn": "arn:branch:two",
                    "branchName": "develop",
                }
            ]
        },
    ]

    client.get_paginator.return_value = paginator

    assert service.list_branches("d111") == [
        {
            "branchArn": "arn:branch:one",
            "branchName": "main",
        },
        {
            "branchArn": "arn:branch:two",
            "branchName": "develop",
        },
    ]

    client.get_paginator.assert_called_once_with(
        "list_branches"
    )

    paginator.paginate.assert_called_once_with(
        appId="d111"
    )


def test_list_branches_returns_empty_for_invalid_app_id():
    service, client = make_service()

    assert service.list_branches("") == []

    client.get_paginator.assert_not_called()


def test_list_tags_for_resource_returns_tags():
    service, client = make_service()

    client.list_tags_for_resource.return_value = {
        "tags": {
            "Environment": "prod",
            "Owner": "security",
        }
    }

    assert service.list_tags_for_resource(
        "arn:resource"
    ) == {
        "Environment": "prod",
        "Owner": "security",
    }

    client.list_tags_for_resource.assert_called_once_with(
        resourceArn="arn:resource"
    )


def test_list_tags_for_resource_returns_empty_for_invalid_arn():
    service, client = make_service()

    assert service.list_tags_for_resource("") == {}

    client.list_tags_for_resource.assert_not_called()


def test_list_apps_normalizes_client_error():
    service, client = make_service()

    error = ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": "denied",
            }
        },
        "ListApps",
    )

    client.get_paginator.side_effect = error

    with pytest.raises(
        RuntimeError,
        match="AccessDeniedException: denied",
    ):
        service.list_apps()
