from unittest.mock import Mock

from scanner.aws.collectors.amplify import (
    AmplifyDataCollector,
)


def make_service():
    return Mock()


def test_collect_apps_normalizes_tags_and_ignores_system_tags():
    service = make_service()

    service.list_apps.return_value = [
        {
            "appId": "d111",
            "appArn": "arn:app:one",
            "name": "frontend",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "Environment": "prod",
        "Owner": "security",
        "aws:createdBy": "system",
    }

    result = AmplifyDataCollector(
        service
    ).collect_apps()

    assert result == [
        {
            "app_id": "d111",
            "app_arn": "arn:app:one",
            "app_name": "frontend",
            "tags": {
                "Environment": "prod",
                "Owner": "security",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        }
    ]


def test_collect_apps_detects_untagged_app():
    service = make_service()

    service.list_apps.return_value = [
        {
            "appId": "d111",
            "appArn": "arn:app:one",
            "name": "frontend",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = AmplifyDataCollector(
        service
    ).collect_apps()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collect_apps_skips_invalid_apps():
    service = make_service()

    service.list_apps.return_value = [
        {
            "appId": "d111",
            "appArn": "arn:app:one",
            "name": "valid",
        },
        {
            "appId": "",
            "appArn": "arn:app:invalid",
            "name": "invalid",
        },
        None,
    ]

    service.list_tags_for_resource.return_value = {}

    result = AmplifyDataCollector(
        service
    ).collect_apps()

    assert len(result) == 1
    assert result[0]["app_name"] == "valid"


def test_collect_apps_uses_app_id_when_name_missing():
    service = make_service()

    service.list_apps.return_value = [
        {
            "appId": "d111",
            "appArn": "arn:app:one",
        }
    ]

    service.list_tags_for_resource.return_value = {}

    result = AmplifyDataCollector(
        service
    ).collect_apps()

    assert result[0]["app_name"] == "d111"


def test_collect_branches_discovers_branches_for_each_app():
    service = make_service()

    service.list_apps.return_value = [
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

    service.list_branches.side_effect = [
        [
            {
                "branchArn": "arn:branch:one",
                "branchName": "main",
            }
        ],
        [
            {
                "branchArn": "arn:branch:two",
                "branchName": "develop",
            }
        ],
    ]

    service.list_tags_for_resource.side_effect = [
        {
            "Environment": "prod",
        },
        {
            "Owner": "security",
        },
    ]

    result = AmplifyDataCollector(
        service
    ).collect_branches()

    assert result == [
        {
            "app_id": "d111",
            "branch_arn": "arn:branch:one",
            "branch_name": "main",
            "tags": {
                "Environment": "prod",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        },
        {
            "app_id": "d222",
            "branch_arn": "arn:branch:two",
            "branch_name": "develop",
            "tags": {
                "Owner": "security",
            },
            "tag_data_available": True,
            "has_non_system_tags": True,
        },
    ]

    assert service.list_branches.call_count == 2


def test_collect_branches_detects_system_only_tags():
    service = make_service()

    service.list_apps.return_value = [
        {
            "appId": "d111",
            "appArn": "arn:app:one",
        }
    ]

    service.list_branches.return_value = [
        {
            "branchArn": "arn:branch:one",
            "branchName": "main",
        }
    ]

    service.list_tags_for_resource.return_value = {
        "aws:createdBy": "system",
    }

    result = AmplifyDataCollector(
        service
    ).collect_branches()

    assert result[0]["tags"] == {}
    assert result[0]["tag_data_available"] is True
    assert result[0]["has_non_system_tags"] is False


def test_collector_caches_app_and_branch_discovery():
    service = make_service()

    service.list_apps.return_value = []
    service.list_branches.return_value = []

    collector = AmplifyDataCollector(service)

    assert collector.collect_apps() == []
    assert collector.collect_apps() == []

    assert collector.collect_branches() == []
    assert collector.collect_branches() == []

    service.list_apps.assert_called_once()
    service.list_branches.assert_not_called()
